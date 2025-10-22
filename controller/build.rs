use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;
use vmlinux;

const SYSCALL_SRC: &str = "src/bpf/syscall.bpf.c";
const HTTP_PROBE_SRC: &str = "src/bpf/http.bpf.c";
const TCP_PROBE_SRC: &str = "src/bpf/network_probe.bpf.c";

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
    .join("network_probe.skel.rs");

    let http_probe_out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("http_probe.skel.rs");


    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(SYSCALL_SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(&arch).as_os_str(),
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
        .source(HTTP_PROBE_SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
        ])
        .build_and_generate(&http_probe_out)
        .unwrap();

    println!("cargo:rerun-if-changed=src/bpf");
}
