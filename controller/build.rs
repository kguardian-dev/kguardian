use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SYSCALL_SRC: &str = "src/bpf/syscall.bpf.c";
const TCP_PROBE_SRC: &str = "src/bpf/tcp_probe.bpf.c";

fn main() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("syscall.skel.rs");

    let tcp_probe_out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("tcp_probe.skel.rs");

    SkeletonBuilder::new()
        .source(SYSCALL_SRC)
        .clang_args([OsStr::new("-I")])
        .build_and_generate(&out)
        .unwrap();

    SkeletonBuilder::new()
        .source(TCP_PROBE_SRC)
        .clang_args([OsStr::new("-I")])
        .build_and_generate(&tcp_probe_out)
        .unwrap();

    println!("cargo:rerun-if-changed=src/bpf");
}
