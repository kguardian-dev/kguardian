// Image signature and ImageTrustPolicy tool support (#1533 P2): argument
// validation and response trimming over the broker's reads
// GET /images/{digest}/attestation (the stored signature result for one
// digest) and GET /image-trust (the evaluator's ImageTrustPolicy results,
// served by the broker). Pure functions; execute.ts does the fetching.
//
// Same rules as vulns.ts: only fields the broker sent are copied, every
// list is count-capped with a sibling `<list>Omitted` count, and every
// result fits MAX_RESPONSE_CHARS with an explicit `truncated` flag. Two
// rules specific to signing: a signature that did not verify never shows a
// signer (a claimed identity is not a fact), and nothing here turns
// unknown, unrecognised_reason or "not evaluated" into a good answer.

import { UNTRUSTED_NOTE, capList, pick } from "./posture.js";
import { hardFit } from "./vulns.js";

type Rec = Record<string, unknown>;

function isRecord(v: unknown): v is Rec {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const clip = (v: unknown, n = 256): unknown =>
  typeof v === "string" && v.length > n ? `${v.slice(0, n)}…` : v;

export const SIGNING_CAPS = {
  signatures: 10,
  attestations: 10,
  policies: 20,
} as const;

// --- the discovery verdict contract (test/fixtures/contracts/attestation-verdicts.json)

export const SIGNATURE_VERDICTS = ["verified", "key_signed", "unsigned", "invalid", "unknown"] as const;

const VERDICT_MEANING: Record<string, string> = {
  verified:
    "a signature verified for the signer(s) listed. Valid, not trusted: anyone with a Fulcio identity or a key can sign, and anyone who can push to the repository can attach a signature. Whether the signer is acceptable is a policy question (explain_image_trust).",
  key_signed:
    "signed with a public key kguardian was not given: the signature exists and was NOT checked, so its signer is not known.",
  unsigned: "no signature was found, and every lookup answered.",
  invalid: "signatures exist and none verified (tampered, wrong digest or malformed). Treat as a failure, never as signed.",
  unknown: "the signatures could not be checked (see reason). Not the same as unsigned, and never a pass.",
};

const REASON_MEANING: Record<string, string> = {
  unrecognised_reason:
    "the checker reported a reason code this broker does not know (a newer supplychain component); the verdict still stands and the reason is unknown, never good",
  registry_auth: "the registry needs credentials kguardian does not have (a private image)",
  trust_root_unavailable: "the Sigstore trust root could not be loaded",
  untrusted_root: "the certificate chains to a root that is not in the configured trust root",
  untrusted_key: "a key signature did not verify against any configured key (or no keys are configured)",
  bad_signature: "a signature did not verify: the content or signature was altered",
  digest_mismatch: "a signature was made for a different digest",
  no_repo_digest: "the image has no registry digest to look signatures up by",
  no_signer_identity: "a signature was marked verified but names no signer (no issuer and SAN, no key fingerprint), so it is not counted as signed: unknown",
};

// --- argument validation -----------------------------------------------------

export const TRUST_VERDICTS = ["Trusted", "WouldDeny", "Unknown"] as const;

/** An ImageTrustPolicy verdict (case-insensitive), or "" = all. */
export function parseTrustVerdict(raw: unknown): string {
  const v = typeof raw === "string" ? raw.trim().toLowerCase().replace(/[-_ ]/g, "") : "";
  if (!v) return "";
  const hit = TRUST_VERDICTS.find((t) => t.toLowerCase() === v);
  if (!hit) throw new Error(`verdict must be one of ${TRUST_VERDICTS.join(", ")}`);
  return hit;
}

// --- GET /images/{digest}/attestation ---------------------------------------

export const SIGNERS_NOTE =
  `verdict: verified (a signature verified), key_signed (signed with a key kguardian was not given: NOT checked), unsigned, invalid (signatures exist, none verified), unknown (could not be checked). "verified" means valid for the listed signer, NOT trusted: only an ImageTrustPolicy (explain_image_trust) says whether a signer is acceptable. unknown, unrecognised_reason, a missing result and key_signed are never a pass. Signers are shown only for signatures that verified; an unverified signature's claimed identity is never a fact. A result marked verified whose signatures name no signer is reported as unknown (reason no_signer_identity, brokerVerdict verified): never signed. kguardian reports only; it never admits or blocks an image. ${UNTRUSTED_NOTE}`;

export const NO_SIGNER_IDENTITY = "no_signer_identity";

/** A signer is named by a keyless issuer AND SAN, or a key fingerprint. */
export function namesSigner(s: Rec): boolean {
  const set = (v: unknown) => typeof v === "string" && v.trim() !== "";
  const keyless = set(s.issuer) && set(s.san);
  if (s.signerKind === "key") return set(s.keyFingerprint);
  if (s.signerKind === undefined || s.signerKind === null || s.signerKind === "") return keyless || set(s.keyFingerprint);
  return keyless;
}

function signer(s: Rec): Rec {
  return s.signerKind === "key"
    ? pick(s, ["signerKind", "keyName", "keyFingerprint"])
    : pick(s, ["signerKind", "issuer", "san"]);
}

/** Result for a digest with no stored signature result (broker 404). */
export function notChecked(digest: string): Rec {
  return {
    found: false,
    digest,
    verdict: "unknown",
    reason: "not_checked",
    note: `kguardian has no signature result for ${digest}: it has not been checked (signature discovery off, the image is not running, or it has not been reached yet). That is unknown, never unsigned and never signed. ${SIGNERS_NOTE}`,
  };
}

export function trimSigners(a: unknown): Rec {
  if (!isRecord(a)) return { found: false, verdict: "unknown", note: SIGNERS_NOTE };
  let verdict = typeof a.verdict === "string" ? a.verdict : "unknown";
  const out: Rec = {
    found: true,
    ...pick(a, ["digest", "repository", "verdict", "reason", "trustRoot", "signedVia", "signedDigest", "checkedAt"]),
  };
  // A signature or attestation marked verified that names no signer (an
  // older broker stored it) is shown as unverified: a claimed "verified"
  // without an identity is not a fact.
  const anonymise = (x: Rec): Rec =>
    x.verified === true && !namesSigner(x) ? { ...x, verified: false, error: NO_SIGNER_IDENTITY, detail: undefined } : x;
  const sigs = (Array.isArray(a.signatures) ? a.signatures : []).filter(isRecord).map(anonymise);
  if (verdict === "verified" && !sigs.some((x) => x.verified === true)) {
    // Verified with no named signer: unknown, never signed.
    verdict = "unknown";
    out.verdict = "unknown";
    out.reason = NO_SIGNER_IDENTITY;
    out.brokerVerdict = "verified";
  }
  // Verified first; the rest keep the broker's order.
  const ordered = [...sigs.filter((s) => s.verified === true), ...sigs.filter((s) => s.verified !== true)];
  const { items, dropped } = capList(ordered, SIGNING_CAPS.signatures);
  out.signatures = (items as Rec[]).map((s) =>
    s.verified === true
      ? { verified: true, ...pick(s, ["format", "source"]), ...signer(s), ...pick(s, ["integratedTime"]) }
      : { verified: false, ...pick(s, ["format", "source", "error"]), ...(s.detail !== undefined ? { detail: clip(s.detail) } : {}) },
  );
  if (dropped > 0) out.signaturesOmitted = dropped;
  // Distinct verified signers, the answer to "who signed this".
  const seen = new Set<string>();
  out.signers = sigs
    .filter((s) => s.verified === true)
    .map(signer)
    .filter((s) => {
      const k = JSON.stringify(s);
      return seen.has(k) ? false : (seen.add(k), true);
    });
  const atts = (Array.isArray(a.attestations) ? a.attestations : []).filter(isRecord).map(anonymise);
  const att = capList(
    [...atts.filter((x) => x.verified === true), ...atts.filter((x) => x.verified !== true)],
    SIGNING_CAPS.attestations,
  );
  out.attestations = (att.items as Rec[]).map((x) =>
    x.verified === true
      ? { verified: true, ...pick(x, ["predicateType"]), ...signer(x), ...pick(x, ["provenance"]) }
      : { verified: false, ...pick(x, ["predicateType", "error"]), ...(x.detail !== undefined ? { detail: clip(x.detail) } : {}) },
  );
  if (att.dropped > 0) out.attestationsOmitted = att.dropped;
  out.verdictMeaning = VERDICT_MEANING[verdict] ?? "an unrecognised verdict: treat as unknown, never as a pass.";
  const reason = typeof out.reason === "string" ? out.reason : "";
  if (reason && REASON_MEANING[reason]) out.reasonMeaning = REASON_MEANING[reason];
  out.truncated = dropped > 0 || att.dropped > 0;
  out.note = SIGNERS_NOTE;
  return hardFit(out, ["signatures", "attestations", "signers"], ["digest", "repository", "verdict", "reason"]);
}

// --- GET /image-trust ----------------------------------------------------------

export const TRUST_REASON_MEANING: Record<string, string> = {
  unsigned: "the image has no signature",
  invalid: "the image's signatures did not verify",
  "untrusted-signer": "signed, but not by any identity or key the policy trusts",
  "key-not-verified": "key-signed with a key kguardian was not given, and the policy trusts a key: give supplychain the key so it can check",
  "attestation-missing": "a required attestation (e.g. SLSA provenance) is missing or not signed by a trusted signer",
  "not-checked": "the image has no signature result yet",
  "namespace-unknown": "the evaluator could not read the namespace's labels, so it cannot tell whether the policy applies",
  "broker-unavailable": "the evaluator could not read signature results from the broker",
  "broker-unauthorized": "the broker refused the evaluator's token",
  no_signer_identity: "the signature result says verified but names no signer, so no authority can match it: unknown",
};

export const TRUST_NOTE =
  `ImageTrustPolicy results are report-only: WouldDeny means an admission controller enforcing this policy would reject the image; kguardian never admits or blocks anything. Unknown (including every discovery reason such as registry_auth or unrecognised_reason) is never a pass. available=false or evaluatedAt=null means there is nothing to report: UNKNOWN, never an all-clear, and total=0 with available=true only means no policy selects the matching workloads. Trusted means a policy's authority signed it, not that the image is safe. ${UNTRUSTED_NOTE}`;

export interface TrustFilters {
  namespace?: string;
  workloadKind?: string;
  workloadName?: string;
  verdict?: string;
}

export function trimImageTrust(page: unknown, filters: TrustFilters): Rec {
  const f: Rec = {};
  for (const [k, v] of Object.entries(filters)) if (v) f[k] = v;
  if (!isRecord(page)) return { available: false, filters: f, truncated: false, note: TRUST_NOTE };
  if (page.available !== true) {
    return {
      available: false,
      reason: clip(page.reason, 512),
      filters: f,
      truncated: false,
      note: `Image trust results are not available, so whether any workload would be denied is UNKNOWN. ${TRUST_NOTE}`,
    };
  }
  const out: Rec = {
    available: true,
    filters: f,
    ...pick(page, ["evaluatedAt", "total", "wouldDeny", "unknown", "trusted"]),
  };
  // A verdict the broker does not count (an older broker, a newer
  // evaluator) is in total and in no count: surface it as Unknown, never
  // let the counts read as all-Trusted.
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : 0);
  const gap = num(page.total) - num(page.wouldDeny) - num(page.unknown) - num(page.trusted);
  if (gap > 0) {
    out.unknown = num(page.unknown) + gap;
    out.unrecognisedVerdicts = gap;
  }
  const pol = capList(Array.isArray(page.policies) ? page.policies : [], SIGNING_CAPS.policies);
  out.policies = pol.items;
  if (pol.dropped > 0) out.policiesOmitted = pol.dropped;
  const results = Array.isArray(page.results) ? page.results.filter(isRecord) : [];
  out.results = results.map((r) => {
    const o = pick(r, ["verdict", "reason", "policy", "namespace", "workload", "container", "image", "digest"]);
    const why = typeof r.reason === "string" ? TRUST_REASON_MEANING[r.reason] : undefined;
    if (why) o.reasonMeaning = why;
    if (!(TRUST_VERDICTS as readonly unknown[]).includes(r.verdict)) {
      o.verdictMeaning = "a verdict this tool does not know: treat it as Unknown, never as Trusted";
    }
    return o;
  });
  const shown = results.length;
  const total = typeof page.total === "number" ? page.total : shown;
  if (total > shown) out.resultsOmitted = total - shown;
  out.truncated = page.truncated === true || total > shown || pol.dropped > 0;
  const lead =
    page.evaluatedAt === null || page.evaluatedAt === undefined
      ? "The evaluator has not finished a pass yet: results are UNKNOWN. "
      : "";
  out.note = `${lead}Results are ordered WouldDeny, Unknown, Trusted; the counts cover every match, results may be cut (truncated). ${TRUST_NOTE}`;
  return hardFit(out, ["results", "policies"], ["available", "evaluatedAt", "total", "wouldDeny", "unknown", "trusted"]);
}
