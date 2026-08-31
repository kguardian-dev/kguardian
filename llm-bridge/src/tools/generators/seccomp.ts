// In-process seccomp profile generator. The assistant generates seccomp
// profiles itself instead of proxying to the advisor service, so the advisor
// Deployment can be retired. This is the same pure function as the frontend's
// buildSeccompProfile (frontend/src/utils/seccompProfileGenerator.ts) and the
// advisor Go BuildSeccompProfile — all three are locked to the shared G2
// fixtures (test/fixtures/generators/seccomp), which is what guarantees one
// behavior everywhere without a shared build (the per-package Docker contexts
// make a monorepo workspace deploy-risky).

export interface SeccompProfile {
  defaultAction: string;
  architectures: string[];
  syscalls: { names: string[]; action: string }[];
}

// Rust std::env::consts::ARCH (controller/src/syscall.rs) → seccomp arch tokens.
const SECCOMP_ARCHITECTURES: Record<string, string[]> = {
  x86_64: ["SCMP_ARCH_X86_64"],
  aarch64: ["SCMP_ARCH_ARM64"],
};

/** Allow-list exactly the observed syscalls, deny the rest. Pure; the allow
 *  rule is always emitted so the shape is stable even with no syscalls. */
export function buildSeccompProfile(syscalls: string[], arch: string): SeccompProfile {
  return {
    defaultAction: "SCMP_ACT_ERRNO",
    architectures: SECCOMP_ARCHITECTURES[arch] ?? [],
    syscalls: [{ names: [...syscalls].sort(), action: "SCMP_ACT_ALLOW" }],
  };
}

/** Reject a profile that would be unusable if applied — a faithful port of the
 *  advisor's k8s.ValidateProfile (pkg/k8s/seccomp.go), which the retired
 *  advisor serve handler ran after building. Without it an unrecognized `arch`
 *  yields `architectures: []` and the generator would silently hand back a
 *  broken profile (its own comment warned "the MCP generate_seccomp_profile
 *  tool silently returns a broken profile"). Throw a clear, actionable error
 *  instead so the tool surfaces it rather than emitting a no-op profile. */
export function validateSeccompProfile(profile: SeccompProfile): void {
  if (!profile.defaultAction) {
    throw new Error("seccomp profile is invalid: default action is required");
  }
  if (profile.architectures.length === 0) {
    throw new Error(
      `seccomp profile is invalid: unrecognized architecture — no seccomp arch mapping (supported: ${Object.keys(SECCOMP_ARCHITECTURES).join(", ")})`,
    );
  }
  if (profile.syscalls.length === 0) {
    throw new Error("seccomp profile is invalid: at least one syscall rule is required");
  }
}

/** Build a profile from a broker /pod/syscalls response ({ syscalls: "a,b,c",
 *  arch }). Comma-split matching the advisor, empty entries dropped. Validated
 *  before return so an unknown arch errors instead of producing a silently
 *  unusable profile (mirrors the advisor build-then-validate flow). */
export function seccompFromBrokerSyscalls(data: unknown): SeccompProfile {
  const rec = (data ?? {}) as { syscalls?: unknown; arch?: unknown };
  const raw = typeof rec.syscalls === "string" ? rec.syscalls : "";
  const arch = typeof rec.arch === "string" ? rec.arch : "";
  const names = raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  const profile = buildSeccompProfile(names, arch);
  validateSeccompProfile(profile);
  return profile;
}
