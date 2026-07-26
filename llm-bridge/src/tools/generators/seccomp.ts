// In-process seccomp profile generator (WS-C). The assistant generates seccomp
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

/** Build a profile from a broker /pod/syscalls response ({ syscalls: "a,b,c",
 *  arch }). Comma-split matching the advisor, empty entries dropped. */
export function seccompFromBrokerSyscalls(data: unknown): SeccompProfile {
  const rec = (data ?? {}) as { syscalls?: unknown; arch?: unknown };
  const raw = typeof rec.syscalls === "string" ? rec.syscalls : "";
  const arch = typeof rec.arch === "string" ? rec.arch : "";
  const names = raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  return buildSeccompProfile(names, arch);
}
