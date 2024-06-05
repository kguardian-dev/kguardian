use aya_tool::generate::InputFile;
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("kube-guardian-ebpf/src");
    let names: Vec<&str> = vec!["sk_buff", "ipv6hdr", "udphdr", "tcphdr"];
    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let mut out = File::create(dir.join("bindings.rs"))?;
    write!(out, "{}", bindings)?;
    Ok(())
}
