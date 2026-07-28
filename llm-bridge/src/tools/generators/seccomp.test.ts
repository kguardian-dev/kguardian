import { test } from "node:test";
import assert from "node:assert/strict";
import { seccompFromBrokerSyscalls, validateSeccompProfile } from "./seccomp.js";

// Regression guard (fix): the assistant's in-process seccomp generator must
// reproduce the advisor serve handler's build-then-validate behavior. An
// unrecognized CPU arch produces `architectures: []`, which the advisor's
// k8s.ValidateProfile rejects — porting the tools in-process originally dropped
// that guard, so an exotic-arch pod would get a silently-broken profile.

test("seccompFromBrokerSyscalls: unknown arch throws instead of a silent broken profile", () => {
  assert.throws(
    () => seccompFromBrokerSyscalls({ syscalls: "read,write", arch: "ppc64le" }),
    /unrecognized architecture/,
  );
  // Missing/empty arch is the same failure mode.
  assert.throws(() => seccompFromBrokerSyscalls({ syscalls: "read", arch: "" }), /unrecognized architecture/);
  assert.throws(() => seccompFromBrokerSyscalls({ syscalls: "read" }), /unrecognized architecture/);
});

test("seccompFromBrokerSyscalls: known arch returns a valid, sorted profile", () => {
  const x86 = seccompFromBrokerSyscalls({ syscalls: "write,read,openat", arch: "x86_64" });
  assert.deepEqual(x86.architectures, ["SCMP_ARCH_X86_64"]);
  assert.equal(x86.defaultAction, "SCMP_ACT_ERRNO");
  assert.deepEqual(x86.syscalls[0].names, ["openat", "read", "write"]);

  const arm = seccompFromBrokerSyscalls({ syscalls: "read", arch: "aarch64" });
  assert.deepEqual(arm.architectures, ["SCMP_ARCH_ARM64"]);
});

test("validateSeccompProfile: mirrors advisor ValidateProfile conditions", () => {
  assert.throws(
    () => validateSeccompProfile({ defaultAction: "", architectures: ["SCMP_ARCH_X86_64"], syscalls: [{ names: ["read"], action: "SCMP_ACT_ALLOW" }] }),
    /default action is required/,
  );
  assert.throws(
    () => validateSeccompProfile({ defaultAction: "SCMP_ACT_ERRNO", architectures: [], syscalls: [{ names: ["read"], action: "SCMP_ACT_ALLOW" }] }),
    /unrecognized architecture/,
  );
  assert.throws(
    () => validateSeccompProfile({ defaultAction: "SCMP_ACT_ERRNO", architectures: ["SCMP_ARCH_X86_64"], syscalls: [] }),
    /at least one syscall rule/,
  );
});
