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

  // The OCI name. SCMP_ARCH_ARM64 is the spelling runc rejects.
  const arm = seccompFromBrokerSyscalls({ syscalls: "read", arch: "aarch64" });
  assert.deepEqual(arm.architectures, ["SCMP_ARCH_AARCH64"]);
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

// The rules-array check counts one, not zero, for the profile that matters:
// a single rule with an empty `names` list. Under a denying defaultAction
// that permits nothing at all, and the container never starts, because the
// filter is installed before execve. Reachable straight from a broker
// response of `{ syscalls: "", arch: "x86_64" }`, and an MCP tool's output
// may be applied without a person reading it.
test("rejects a denying default that allows no syscall by name", () => {
  assert.throws(
    () => validateSeccompProfile({
      defaultAction: "SCMP_ACT_ERRNO",
      architectures: ["SCMP_ARCH_X86_64"],
      syscalls: [{ names: [], action: "SCMP_ACT_ALLOW" }],
    }),
    /no rule allows any syscall/,
  );
});

test("rejects it via the broker-response path too", () => {
  assert.throws(
    () => seccompFromBrokerSyscalls({ syscalls: "", arch: "x86_64" }),
    /no rule allows any syscall/,
  );
});

test("accepts a denying default once one rule allows something", () => {
  assert.doesNotThrow(() =>
    seccompFromBrokerSyscalls({ syscalls: "read,write", arch: "x86_64" }),
  );
});

// A permissive default with an empty rule is a no-op rather than a trap, so
// the check must not fire: audit-only profiles legitimately allow nothing by
// name and still let the workload run.
test("accepts a permissive default with an empty rule", () => {
  assert.doesNotThrow(() =>
    validateSeccompProfile({
      defaultAction: "SCMP_ACT_LOG",
      architectures: ["SCMP_ARCH_X86_64"],
      syscalls: [{ names: [], action: "SCMP_ACT_ALLOW" }],
    }),
  );
});
