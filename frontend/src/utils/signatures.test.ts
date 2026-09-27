import { expect, test } from 'vitest';
import { vulnCapture } from '../fixtures/vulns';
import type { AttestationPage, ImageAttestation, RunningSignaturePage } from '../types/attestations';
import type { WorkloadProfile } from '../types/profile';
import {
  asSignatureState,
  reasonText,
  SIGNATURE_TONE,
  signatureBadgeText,
  signaturesByDigest,
  signaturesByWorkload,
  signerOf,
  signerShort,
  signerText,
  splitHeader,
  summaryFromProfile,
  workloadSignatureText,
} from './signatures';
import { workloadKey } from './workloads';

const running = vulnCapture<RunningSignaturePage>('attestations-running');
const byDigest = signaturesByDigest(running.body.items);
const repoState = Object.fromEntries(byDigest.map((d) => [d.repository, d.state]));
const byWorkload = signaturesByWorkload(running.body.items, workloadKey);

test('the running feed is captured from a real Broker', () => {
  expect(running.provenance).toMatch(/^captured from broker [0-9a-f]{7,}/);
  expect(running.status).toBe(200);
});

test('every captured digest maps to its state; a digest with no result is "not checked", never unsigned', () => {
  expect(repoState).toEqual({
    'ghcr.io/example/checkout': 'verified',
    'ghcr.io/example/ledger': 'verified',
    'ghcr.io/example/reports': 'unsigned',
    'docker.io/grafana/grafana': 'key_signed',
    'quay.io/prometheus/prometheus': 'invalid',
    'quay.io/prometheus/node-exporter': 'unknown',
    'ghcr.io/fluxcd/source-controller': 'unknown',
    'registry.k8s.io/ingress-nginx/controller': 'unchecked',
  });
  // Worst first.
  expect(byDigest[0].state).toBe('invalid');
  expect(byDigest.at(-1)!.state).toBe('verified');
});

test('an unrecognised reason is stored by the Broker as unrecognised_reason and read as unknown, in words', () => {
  const sc = byDigest.find((d) => d.repository === 'ghcr.io/fluxcd/source-controller')!;
  expect(sc.reason).toBe('unrecognised_reason');
  expect(reasonText(sc.reason)).toMatch(/does not know/);
  expect(reasonText('some_future_code')).toBe('reason "some_future_code"');
});

test('a verdict string the UI does not know is unknown, never good', () => {
  expect(asSignatureState('trusted')).toBe('unknown');
  expect(asSignatureState(null)).toBe('unchecked');
  expect(asSignatureState(undefined)).toBe('unchecked');
});

test('verified is never the good tone: a valid signature is not a trusted signer', () => {
  expect(SIGNATURE_TONE.verified).toBe('neutral');
  for (const s of ['unknown', 'unchecked', 'key_signed'] as const) expect(SIGNATURE_TONE[s]).toBe('unknown');
  expect(Object.values(SIGNATURE_TONE)).not.toContain('good');
});

test('verified carries its signer in full: keyless identity and configured key', () => {
  const checkout = byDigest.find((d) => d.repository === 'ghcr.io/example/checkout')!;
  expect(checkout.signers).toHaveLength(1);
  expect(signerText(checkout.signers[0])).toBe('https://github.com/example-org/checkout/.github/workflows/release.yaml@refs/tags/v4.2.0 via https://token.actions.githubusercontent.com');
  expect(signerShort(checkout.signers[0])).toBe('example-org/checkout release.yaml');
  expect(checkout.predicates).toEqual(['https://slsa.dev/provenance/v1']);
  expect(checkout.source).toBe('https://github.com/example-org/checkout @ refs/tags/v4.2.0');
  const ledger = byDigest.find((d) => d.repository === 'ghcr.io/example/ledger')!;
  expect(signerText(ledger.signers[0])).toBe('key payments-release (sha256:d4d97426189e…)');
});

test('an unverified signature never yields a signer (a claimed identity is not a fact)', () => {
  const grafana = byDigest.find((d) => d.repository === 'docker.io/grafana/grafana')!;
  expect(grafana.signers).toEqual([]);
  // The single read keeps unverified signatures (error + key hint): none becomes a signer.
  const single = vulnCapture<ImageAttestation>('attestation-grafana').body;
  expect(single.signatures).toHaveLength(1);
  expect(single.signatures[0]).toMatchObject({ verified: false, error: 'untrusted_key', keyHint: 'grafana-release' });
  expect(single.signatures.map(signerOf)).toEqual([null]);
  const summaries = vulnCapture<AttestationPage>('attestations').body.items;
  for (const s of summaries) if (s.verdict !== 'verified') expect(s.signers).toEqual([]);
});

test('a workload reads as its worst image, and the text says what is unknown', () => {
  const checkout = byWorkload.get(workloadKey('payments', 'Deployment', 'checkout'))!;
  expect(checkout.worst).toBe('verified');
  expect(signatureBadgeText(checkout)).toBe('signed');
  expect(workloadSignatureText(checkout)).toMatch(/not vetted/);

  // A verified image plus one not checked is not "signed".
  const mixed = signaturesByWorkload(
    [...running.body.items.filter((i) => i.workloadName === 'checkout'), { ...running.body.items.find((i) => i.workloadName === 'ingress-nginx-controller')!, namespace: 'payments', workloadKind: 'Deployment', workloadName: 'checkout', container: 'sidecar' }],
    workloadKey,
  ).get(workloadKey('payments', 'Deployment', 'checkout'))!;
  expect(mixed.worst).toBe('unchecked');
  expect(signatureBadgeText(mixed)).toBe('not checked 1/2');
  expect(workloadSignatureText(mixed)).toMatch(/1 not checked, 1 verified/);
  expect(SIGNATURE_TONE[mixed.worst]).toBe('unknown');
});

test('the captured policy header splits from its YAML and keeps the review warning', () => {
  const text = vulnCapture<string>('policy-kguardian-audit').body;
  const { header, body } = splitHeader(text);
  expect(header).toContain('REVIEW EVERY IDENTITY BEFORE APPLYING: identities were observed on running images, not vetted.');
  expect(header.filter((l) => l.startsWith('identity:'))).toHaveLength(2);
  expect(header.some((l) => l.startsWith('not covered: registry.k8s.io/ingress-nginx/controller'))).toBe(true);
  expect(body.startsWith('apiVersion: kguardian.dev/v1alpha1')).toBe(true);
  expect(body).not.toMatch(/^#/m);
});

test('"verified" with no verified signer is unknown, for the digest and the workload: never signed without its signer', () => {
  const stripped = running.body.items.map((i) => (i.workloadName === 'checkout' ? { ...i, signers: [] } : i));
  const d = signaturesByDigest(stripped).find((x) => x.repository === 'ghcr.io/example/checkout')!;
  expect(d).toMatchObject({ state: 'unknown', noSigner: true, signers: [] });
  const w = signaturesByWorkload(stripped, workloadKey).get(workloadKey('payments', 'Deployment', 'checkout'))!;
  expect(w.worst).toBe('unknown');
  expect(signatureBadgeText(w)).toBe('sig unknown');
  expect(workloadSignatureText(w)).not.toMatch(/has a verified signature/);
  // An unverified check does not count as a signer either.
  const claimed = running.body.items.map((i) => (i.workloadName === 'checkout' ? { ...i, signers: i.signers.map((c) => ({ ...c, verified: false })) } : i));
  expect(signaturesByDigest(claimed).find((x) => x.repository === 'ghcr.io/example/checkout')!.state).toBe('unknown');
});

test('profile supplyChain (v1.8): verified with only blank signer identities is unknown, not signed', () => {
  const sc = vulnCapture<WorkloadProfile>('signature-profile-checkout').body.dimensions.images.supplyChain!;
  expect(summaryFromProfile(sc)!.worst).toBe('verified');
  const blank = { ...sc, signers: [{ signerKind: 'keyless', issuer: '  ', san: sc.signers[0].san }, { signerKind: 'key', keyName: 'k', keyFingerprint: '' }] };
  expect(summaryFromProfile(blank)!.worst).toBe('unknown');
  expect(summaryFromProfile({ ...sc, status: 'not_configured', verdict: 'not_configured' })).toBeNull();
  const never = vulnCapture<WorkloadProfile>('signature-profile-ingress-nginx-controller').body.dimensions.images.supplyChain!;
  expect([never.verdict, never.reason]).toEqual(['unknown', 'not_checked']);
  expect(summaryFromProfile(never)!.worst).toBe('unchecked');
});
