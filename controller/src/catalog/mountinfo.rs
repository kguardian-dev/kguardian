//! `/proc/<pid>/mountinfo`, read for the three facts the catalog needs
//! about a container's root: what filesystem it is, what is mounted
//! beneath it, and where its overlay upperdir lives on the host.
//!
//! Pure over the file body, so every case — including the lines real
//! nodes produce — is a unit test.
//!
//! What this deliberately does NOT do (design, final review item 2):
//!
//! * **Validate lowerdirs.** containerd compacts long lowerdir lists to
//!   paths relative to a common parent it `chdir`s into before
//!   mounting, so `lowerdir=52/fs:51/fs` is a legitimate, un-resolvable
//!   string here. Nothing downstream needs them.
//! * **Trust the upperdir as a path.** It is a host path string, and is
//!   only ever resolved by `root::drift_check` under `/proc/1/root` with
//!   `RESOLVE_IN_ROOT`. Parsing only decides whether it is usable at all;
//!   an absent or unparseable one makes drift unknown, and the SBOM is
//!   then `partial`, never `full`.

/// At most this many submounts are sent (PROTOCOL.md 3.2).
pub const MAX_SUBMOUNTS: usize = 1024;
/// Longest submount path sent (PROTOCOL.md 3.2).
pub const MAX_SUBMOUNT_LEN: usize = 4096;

/// One parsed mountinfo line (only the fields used here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub mount_id: u64,
    pub parent_id: u64,
    /// Mount point, unescaped. Raw bytes: a mount point need not be UTF-8.
    pub mount_point: Vec<u8>,
    pub fs_type: String,
    pub source: Vec<u8>,
    /// Super options, split on unescaped commas, each unescaped.
    pub super_options: Vec<Vec<u8>>,
}

/// Why a container root cannot be catalogued. These are the broker's
/// per-node skip reasons of the same names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootRefusal {
    /// The root is served lazily (stargz, SOCI, nydus, or any FUSE
    /// filesystem): reading it would pull the image over the network,
    /// and a partially fetched root is not the image.
    LazySnapshotter,
    /// Anything that is not overlayfs, or a mountinfo without a root.
    UnsupportedRootfs,
}

impl RootRefusal {
    pub fn reason(self) -> &'static str {
        match self {
            RootRefusal::LazySnapshotter => "lazy_snapshotter",
            RootRefusal::UnsupportedRootfs => "unsupported_rootfs",
        }
    }
}

/// The upperdir, as far as it could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upperdir {
    /// An absolute, clean host path.
    Path(String),
    /// No upperdir option at all (a read-only overlay, or a runtime that
    /// hides it).
    Missing,
    /// An upperdir option whose value cannot be used as a path.
    Unparseable,
}

/// What the catalog needs from a container's mountinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootInfo {
    pub upperdir: Upperdir,
    /// Every mount point other than `/`: absolute, clean, UTF-8, sorted,
    /// unique, at most [`MAX_SUBMOUNTS`].
    pub submounts: Vec<String>,
    /// Submounts left out (non-UTF-8, over-long, or over the count).
    /// The worker refuses to cross any mount on its own, so this is a
    /// log line, not a correctness problem.
    pub submounts_dropped: usize,
}

/// Undo the kernel's octal escaping (`\040` space, `\011` tab, `\012`
/// newline, `\134` backslash, and `\054` comma in overlay options).
/// `None` for a backslash not followed by three octal digits, which the
/// kernel never writes.
pub fn unescape(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            let oct = b.get(i + 1..i + 4)?;
            if !oct.iter().all(|c| (b'0'..=b'7').contains(c)) {
                return None;
            }
            let v = u32::from(oct[0] - b'0') * 64
                + u32::from(oct[1] - b'0') * 8
                + u32::from(oct[2] - b'0');
            out.push(u8::try_from(v).ok()?);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Parse one line. `None` for a line that is not a mountinfo record.
pub fn parse_line(line: &str) -> Option<MountEntry> {
    let fields: Vec<&str> = line.split(' ').filter(|f| !f.is_empty()).collect();
    // id parent maj:min root mount-point options [optional...] - fstype source superopts
    let sep = fields.iter().position(|f| *f == "-")?;
    if sep < 6 || fields.len() < sep + 3 {
        return None;
    }
    let mount_id = fields[0].parse().ok()?;
    let parent_id = fields[1].parse().ok()?;
    let mount_point = unescape(fields[4])?;
    let fs_type = String::from_utf8(unescape(fields[sep + 1])?).ok()?;
    let source = unescape(fields[sep + 2])?;
    // Split BEFORE unescaping: an escaped comma (`\054`) is part of a
    // value, a raw one separates options.
    let super_options = match fields.get(sep + 3) {
        Some(opts) => opts
            .split(',')
            .map(unescape)
            .collect::<Option<Vec<_>>>()
            .unwrap_or_else(|| vec![b"\0unparseable".to_vec()]),
        None => Vec::new(),
    };
    Some(MountEntry {
        mount_id,
        parent_id,
        mount_point,
        fs_type,
        source,
        super_options,
    })
}

/// Parse a whole body; lines that do not parse are skipped.
pub fn parse(body: &str) -> Vec<MountEntry> {
    body.lines().filter_map(parse_line).collect()
}

/// An absolute path with no empty, `.` or `..` component and no NUL.
fn clean_absolute(p: &[u8]) -> bool {
    if p.first() != Some(&b'/') || p.contains(&0) {
        return false;
    }
    if p == b"/" {
        return true;
    }
    p[1..]
        .split(|c| *c == b'/')
        .all(|seg| !seg.is_empty() && seg != b"." && seg != b"..")
}

/// Is this filesystem a lazily-pulling one? FUSE (`fuse`, `fuse.*`,
/// `fuseblk`) covers stargz and SOCI, which mount each layer over FUSE;
/// nydus shows up as `fuse.nydus-overlayfs`, or as erofs over fscache.
fn is_lazy_fs(fs_type: &str) -> bool {
    let t = fs_type.to_ascii_lowercase();
    t == "fuse" || t == "fuseblk" || t.starts_with("fuse.") || t.contains("nydus")
}

/// Lowerdirs that name a lazy snapshotter's own directory. Only a hint:
/// lowerdirs are not validated and may be relative (see module docs), so
/// the absence of one proves nothing. When present, it is conclusive:
/// overlay over stargz/SOCI/nydus layers reads through FUSE.
fn lowerdir_is_lazy(opt: &[u8]) -> bool {
    let Some(v) = opt
        .strip_prefix(b"lowerdir=")
        .or_else(|| opt.strip_prefix(b"lowerdir+="))
    else {
        return false;
    };
    let v = String::from_utf8_lossy(v).to_ascii_lowercase();
    ["stargz", "soci-snapshotter", "nydus"]
        .iter()
        .any(|m| v.contains(m))
}

fn upperdir_of(opts: &[Vec<u8>]) -> Upperdir {
    let mut found = None;
    for o in opts {
        if o.first() == Some(&0) {
            // The options field did not unescape: nothing in it can be
            // trusted, including an upperdir that happens to look fine.
            return Upperdir::Unparseable;
        }
        if let Some(v) = o.strip_prefix(b"upperdir=") {
            if found.is_some() {
                // Two upperdirs is not something overlayfs produces.
                return Upperdir::Unparseable;
            }
            found = Some(v.to_vec());
        }
    }
    match found {
        None => Upperdir::Missing,
        Some(v) if clean_absolute(&v) && v != b"/" => match String::from_utf8(v) {
            Ok(s) => Upperdir::Path(s),
            Err(_) => Upperdir::Unparseable,
        },
        Some(_) => Upperdir::Unparseable,
    }
}

/// The container root from its mountinfo.
///
/// The root is the LAST entry mounted at `/`: a later mount on the same
/// point is stacked on the earlier one, and the stack's top is what
/// `/proc/<pid>/root` resolves to.
pub fn root_info(entries: &[MountEntry]) -> Result<RootInfo, RootRefusal> {
    let root = entries
        .iter()
        .rev()
        .find(|e| e.mount_point == b"/")
        .ok_or(RootRefusal::UnsupportedRootfs)?;
    if is_lazy_fs(&root.fs_type) {
        return Err(RootRefusal::LazySnapshotter);
    }
    if root.fs_type != "overlay" {
        return Err(RootRefusal::UnsupportedRootfs);
    }
    if root.super_options.iter().any(|o| lowerdir_is_lazy(o)) {
        return Err(RootRefusal::LazySnapshotter);
    }
    let upperdir = upperdir_of(&root.super_options);

    let mut submounts: Vec<String> = Vec::new();
    let mut dropped = 0usize;
    for e in entries {
        if e.mount_point == b"/" {
            continue;
        }
        let ok = clean_absolute(&e.mount_point) && e.mount_point.len() <= MAX_SUBMOUNT_LEN;
        match (ok, std::str::from_utf8(&e.mount_point)) {
            (true, Ok(s)) => submounts.push(s.to_string()),
            _ => dropped += 1,
        }
    }
    submounts.sort();
    submounts.dedup();
    if submounts.len() > MAX_SUBMOUNTS {
        dropped += submounts.len() - MAX_SUBMOUNTS;
        submounts.truncate(MAX_SUBMOUNTS);
    }
    Ok(RootInfo {
        upperdir,
        submounts,
        submounts_dropped: dropped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// containerd 2.2 on Bottlerocket 1.66 (kernel 6.12), an nginx pod:
    /// the overlay root with SELinux context options, the usual kubelet
    /// bind mounts, a projected SA token and an emptyDir. Paths as
    /// Bottlerocket lays them out (containerd state on /var/lib).
    const BOTTLEROCKET: &str = "\
1893 1735 0:412 / / rw,relatime master:627 - overlay overlay rw,seclabel,context=\"system_u:object_r:data_t:s0\",lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2291/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2290/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2305/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2305/work,uuid=on
1894 1893 0:415 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1895 1893 0:416 / /dev rw,nosuid - tmpfs tmpfs rw,seclabel,size=65536k,mode=755
1896 1895 0:417 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,seclabel,gid=5,mode=620,ptmxmode=666
1897 1895 0:405 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw,seclabel
1898 1893 0:418 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro,seclabel
1899 1898 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,seclabel,nsdelegate,memory_recursiveprot
1900 1893 259:3 /var/lib/kubelet/pods/5d7c-uid/volumes/kubernetes.io~empty-dir/cache /var/cache/nginx rw,nosuid,nodev,noatime - xfs /dev/nvme1n1p1 rw,seclabel,attr2,inode64,logbufs=8,logbsize=32k,noquota
1901 1893 259:3 /var/lib/kubelet/pods/5d7c-uid/etc-hosts /etc/hosts rw,nosuid,nodev,noatime - xfs /dev/nvme1n1p1 rw,seclabel
1902 1895 259:3 /var/lib/kubelet/pods/5d7c-uid/containers/nginx/0b1f /dev/termination-log rw,nosuid,nodev,noatime - xfs /dev/nvme1n1p1 rw,seclabel
1903 1893 259:3 /var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/9a1/hostname /etc/hostname rw,nosuid,nodev,noatime - xfs /dev/nvme1n1p1 rw,seclabel
1904 1893 259:3 /var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/9a1/resolv.conf /etc/resolv.conf rw,nosuid,nodev,noatime - xfs /dev/nvme1n1p1 rw,seclabel
1905 1895 0:404 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,seclabel,size=65536k
1906 1893 0:399 / /run/secrets/kubernetes.io/serviceaccount ro,relatime - tmpfs tmpfs rw,seclabel,size=7976832k
";

    #[test]
    fn bottlerocket_containerd_22_root_is_overlay_with_its_upperdir() {
        let info = root_info(&parse(BOTTLEROCKET)).expect("overlay root");
        assert_eq!(
            info.upperdir,
            Upperdir::Path(
                "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2305/fs"
                    .into()
            )
        );
        assert_eq!(
            info.submounts,
            vec![
                "/dev",
                "/dev/mqueue",
                "/dev/pts",
                "/dev/shm",
                "/dev/termination-log",
                "/etc/hostname",
                "/etc/hosts",
                "/etc/resolv.conf",
                "/proc",
                "/run/secrets/kubernetes.io/serviceaccount",
                "/sys",
                "/sys/fs/cgroup",
                "/var/cache/nginx",
            ]
        );
        assert_eq!(info.submounts_dropped, 0);
    }

    /// containerd 2.x through the new mount API on kernel >= 6.5 shows
    /// one `lowerdir+=` per layer, and compacts lowerdirs to relative
    /// paths when the list is long. Neither is validated.
    #[test]
    fn lowerdir_plus_and_relative_lowerdirs_are_not_validated() {
        let line = "40 30 0:50 / / rw,relatime - overlay overlay rw,lowerdir+=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs,lowerdir+=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/8/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12/work";
        let info = root_info(&parse(line)).unwrap();
        assert!(matches!(info.upperdir, Upperdir::Path(_)));

        let compacted = "40 30 0:50 / / rw - overlay overlay rw,lowerdir=52/fs:51/fs:50/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/60/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/60/work";
        let info = root_info(&parse(compacted)).unwrap();
        assert_eq!(
            info.upperdir,
            Upperdir::Path(
                "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/60/fs".into()
            )
        );
    }

    #[test]
    fn stargz_soci_and_fuse_roots_are_lazy_snapshotters() {
        // stargz: overlay whose layers are FUSE mounts under its own dir.
        let stargz = "50 40 0:60 / / rw - overlay overlay rw,lowerdir=/var/lib/containerd-stargz-grpc/snapshotter/snapshots/7/fs,upperdir=/var/lib/containerd-stargz-grpc/snapshotter/snapshots/9/fs,workdir=/var/lib/containerd-stargz-grpc/snapshotter/snapshots/9/work";
        assert_eq!(root_info(&parse(stargz)), Err(RootRefusal::LazySnapshotter));
        let soci = "50 40 0:60 / / rw - overlay overlay rw,lowerdir=/var/lib/soci-snapshotter-grpc/snapshotter/snapshots/3/fs,upperdir=/var/lib/soci-snapshotter-grpc/snapshotter/snapshots/4/fs,workdir=/w";
        assert_eq!(root_info(&parse(soci)), Err(RootRefusal::LazySnapshotter));
        // A FUSE root outright, and nydus's overlay shim.
        let fuse = "50 40 0:61 / / rw,nosuid,nodev - fuse.rawBridge stargz rw,user_id=0,group_id=0";
        assert_eq!(root_info(&parse(fuse)), Err(RootRefusal::LazySnapshotter));
        let nydus = "50 40 0:62 / / rw - fuse.nydus-overlayfs overlay rw,lowerdir=/x";
        assert_eq!(root_info(&parse(nydus)), Err(RootRefusal::LazySnapshotter));
    }

    #[test]
    fn other_root_filesystems_are_unsupported() {
        let ext4 = "50 40 8:1 / / rw,relatime - ext4 /dev/sda1 rw";
        assert_eq!(root_info(&parse(ext4)), Err(RootRefusal::UnsupportedRootfs));
        // A gVisor/Kata-shaped view: 9p or virtiofs root.
        let v9p = "50 40 0:70 / / rw - 9p none rw,trans=fd";
        assert_eq!(root_info(&parse(v9p)), Err(RootRefusal::UnsupportedRootfs));
        assert_eq!(root_info(&[]), Err(RootRefusal::UnsupportedRootfs));
        assert_eq!(
            root_info(&parse("garbage\nmore garbage")),
            Err(RootRefusal::UnsupportedRootfs)
        );
    }

    #[test]
    fn a_later_mount_on_root_wins() {
        // A tmpfs stacked over the overlay root is what /proc/<pid>/root
        // resolves to; it must not be judged by the overlay under it.
        let body = "\
50 40 0:60 / / rw - overlay overlay rw,upperdir=/u/fs,workdir=/u/work
51 50 0:61 / / rw - tmpfs tmpfs rw
";
        assert_eq!(root_info(&parse(body)), Err(RootRefusal::UnsupportedRootfs));
    }

    #[test]
    fn escapes_in_mount_points_and_options_are_undone() {
        let body = "\
50 40 0:60 / / rw - overlay overlay rw,lowerdir=/l,upperdir=/var/lib/snap\\054shots/with\\040space/fs,workdir=/w
51 50 0:61 / /data\\040dir rw - tmpfs tmpfs rw
52 50 0:62 / /tab\\011and\\012newline rw - tmpfs tmpfs rw
53 50 0:63 / /back\\134slash rw - tmpfs tmpfs rw
";
        let info = root_info(&parse(body)).unwrap();
        // The escaped comma is part of the value, not an option break.
        assert_eq!(
            info.upperdir,
            Upperdir::Path("/var/lib/snap,shots/with space/fs".into())
        );
        assert_eq!(
            info.submounts,
            vec!["/back\\slash", "/data dir", "/tab\tand\nnewline"]
        );
    }

    #[test]
    fn non_utf8_and_unclean_submounts_are_dropped_and_counted() {
        let body = "\
50 40 0:60 / / rw - overlay overlay rw,upperdir=/u/fs
51 50 0:61 / /bad\\377name rw - tmpfs tmpfs rw
52 50 0:62 / /ok rw - tmpfs tmpfs rw
";
        let info = root_info(&parse(body)).unwrap();
        assert_eq!(info.submounts, vec!["/ok"]);
        assert_eq!(info.submounts_dropped, 1);
    }

    #[test]
    fn unparseable_or_missing_upperdirs_are_told_apart() {
        let cases = [
            // Relative: not resolvable under /proc/1/root as a host path.
            ("upperdir=snapshots/9/fs", Upperdir::Unparseable),
            // Dot-dot, empty, and NUL-carrying values.
            ("upperdir=/var/../etc", Upperdir::Unparseable),
            ("upperdir=", Upperdir::Unparseable),
            ("upperdir=/a//b", Upperdir::Unparseable),
            ("upperdir=/a\\000b", Upperdir::Unparseable),
            // A bad escape anywhere poisons the whole options field.
            ("lowerdir=/l\\9zz,upperdir=/u/fs", Upperdir::Unparseable),
            // Two upperdirs.
            ("upperdir=/a/fs,upperdir=/b/fs", Upperdir::Unparseable),
            // Non-UTF-8.
            ("upperdir=/a\\377/fs", Upperdir::Unparseable),
            // None at all: a read-only overlay.
            ("lowerdir=/a:/b", Upperdir::Missing),
        ];
        for (opts, want) in cases {
            let line = format!("50 40 0:60 / / rw - overlay overlay rw,{opts}");
            let info = root_info(&parse(&line)).unwrap_or_else(|e| panic!("{opts}: {e:?}"));
            assert_eq!(info.upperdir, want, "{opts}");
        }
    }

    #[test]
    fn optional_fields_before_the_separator_are_skipped() {
        let line = "50 40 0:60 / / rw,relatime shared:1 master:2 propagate_from:3 - overlay overlay rw,upperdir=/u/fs";
        let e = parse_line(line).unwrap();
        assert_eq!(e.fs_type, "overlay");
        assert_eq!(e.mount_id, 50);
        assert_eq!(e.parent_id, 40);
    }

    #[test]
    fn submounts_are_capped() {
        let mut body = String::from("1 0 0:1 / / rw - overlay overlay rw,upperdir=/u/fs\n");
        for i in 0..(MAX_SUBMOUNTS + 10) {
            body.push_str(&format!("{} 1 0:2 / /m{i:05} rw - tmpfs tmpfs rw\n", i + 2));
        }
        let info = root_info(&parse(&body)).unwrap();
        assert_eq!(info.submounts.len(), MAX_SUBMOUNTS);
        assert_eq!(info.submounts_dropped, 10);
    }

    #[test]
    fn unescape_rejects_malformed_escapes() {
        assert_eq!(unescape("a\\04"), None);
        assert_eq!(unescape("a\\0x9"), None);
        assert_eq!(unescape("a\\777"), None); // 511 does not fit a byte
        assert_eq!(unescape("plain").unwrap(), b"plain");
    }
}
