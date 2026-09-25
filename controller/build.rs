use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SYSCALL_SRC: &str = "src/bpf/syscall.bpf.c";
const TCP_PROBE_SRC: &str = "src/bpf/network_probe.bpf.c";
const PACKET_DROP_SRC: &str = "src/bpf/netpolicy_drop.bpf.c";
const SCHED_CONTENTION_SRC: &str = "src/bpf/sched_contention.bpf.c";
const SECCOMP_DENIAL_SRC: &str = "src/bpf/seccomp_denial.bpf.c";

fn main() {
    // Generated skeletons go to OUT_DIR, never into the source tree.
    //
    // They used to be written to src/bpf/ and committed. Their content
    // is architecture-dependent (the vmlinux include path below is
    // selected by CARGO_CFG_TARGET_ARCH), so whichever machine built
    // last owned ~25k lines of the diff, and a one-line change to a
    // .bpf.c rewrote all three files. That buried real changes and made
    // the tracked copies disagree with what any given build produces.
    //
    // Nothing consumed the committed copies: every build regenerates
    // them before compiling, so they were never an input, a fallback,
    // or a checked artifact. Cargo's contract is that a build script
    // confines its writes to OUT_DIR, and the include! sites in
    // network.rs / syscall.rs read them from there.
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));

    let out = out_dir.join("syscall.skel.rs");
    let pkt_drop_out = out_dir.join("netpolicy_drop.skel.rs");
    let tcp_probe_out = out_dir.join("network_probe.skel.rs");
    let sched_contention_out = out_dir.join("sched_contention.skel.rs");
    let seccomp_denial_out = out_dir.join("seccomp_denial.skel.rs");
    // The sched_contention object is also kept on disk (the skeleton
    // embeds a copy of exactly this file) so
    // contention::tests::embedded_object_uses_legacy_xadd_atomics can
    // inspect the instruction encoding.
    let sched_contention_obj = out_dir.join("sched_contention.bpf.o");
    // Same arrangement for the seccomp denial object, read by
    // seccomp_denial::tests::embedded_object_uses_legacy_xadd_atomics.
    let seccomp_denial_obj = out_dir.join("seccomp_denial.bpf.o");
    // And the syscall object, read by
    // early_capture::tests::embedded_syscall_object_uses_legacy_xadd_atomics.
    let syscall_obj = out_dir.join("syscall.bpf.o");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    // -mcpu=v2 for the same reason as sched_contention below: the
    // startup-capture gate counts marks with __sync_fetch_and_add, whose
    // v3 lowering (BPF_ATOMIC|BPF_FETCH) the verifier rejects before 5.12
    // and the arm64 JIT before 5.18. This object carries the REQUIRED
    // syscall probe, so an encoding a kernel refuses would cost syscall
    // capture itself (bpf.rs does retry without the startup program).
    SkeletonBuilder::new()
        .source(SYSCALL_SRC)
        .obj(&syscall_obj)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(&arch).as_os_str(),
            OsStr::new("-mcpu=v2"),
        ])
        .build_and_generate(&out)
        .unwrap();

    SkeletonBuilder::new()
        .source(TCP_PROBE_SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(&arch).as_os_str(),
        ])
        .build_and_generate(&tcp_probe_out)
        .unwrap();

    SkeletonBuilder::new()
        .source(PACKET_DROP_SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(&arch).as_os_str(),
        ])
        .build_and_generate(&pkt_drop_out)
        .unwrap();

    // -mcpu=v2 pins the atomics encoding. Recent clang (>= 18 or so)
    // defaults the BPF target to cpu v3 and lowers __sync_fetch_and_add
    // to BPF_ATOMIC|BPF_FETCH, which the verifier rejects on kernels
    // before 5.12 and the arm64 JIT before 5.18. On v2 it lowers to the
    // legacy BPF_XADD every supported kernel accepts. Only this probe
    // carries the flag: the other three have the same exposure but are
    // left as they are here on purpose (contract Deviations, follow-up).
    // contention::tests::embedded_object_uses_legacy_xadd_atomics fails
    // the build's test run if a toolchain change undoes this.
    SkeletonBuilder::new()
        .source(SCHED_CONTENTION_SRC)
        .obj(&sched_contention_obj)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(&arch).as_os_str(),
            OsStr::new("-mcpu=v2"),
        ])
        .build_and_generate(&sched_contention_out)
        .unwrap();

    // -mcpu=v2 for the same reason as sched_contention above: this probe
    // counts verdicts in place with __sync_fetch_and_add, and the v3
    // lowering of that (BPF_ATOMIC|BPF_FETCH) is rejected by the verifier
    // before 5.12 and by the arm64 JIT before 5.18. Unlike the other
    // three, dropping the flag here is not a latent exposure — it is an
    // immediate load failure on those kernels, on a probe whose entire
    // point is to keep working on kernels that lack newer features.
    // seccomp_denial::tests::embedded_object_uses_legacy_xadd_atomics
    // fails the build's test run if a toolchain change undoes this.
    SkeletonBuilder::new()
        .source(SECCOMP_DENIAL_SRC)
        .obj(&seccomp_denial_obj)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
            OsStr::new("-mcpu=v2"),
        ])
        .build_and_generate(&seccomp_denial_out)
        .unwrap();

    println!("cargo:rerun-if-changed=src/bpf");
}
