package sandbox

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Caps is a process's capability sets as bitmasks.
type Caps struct {
	Effective   uint64 `json:"effective"`
	Permitted   uint64 `json:"permitted"`
	Inheritable uint64 `json:"inheritable"`
	Ambient     uint64 `json:"ambient"`
}

// Bit returns the mask for one capability.
func Bit(c int) uint64 { return 1 << uint(c) }

// Capability sets of the process model (README "Process model").
var (
	// ParentAllowed: the worker parent keeps only what it needs to start a
	// scan child as another uid with CAP_DAC_READ_SEARCH in its ambient set.
	ParentAllowed = Bit(unix.CAP_DAC_READ_SEARCH) | Bit(unix.CAP_SETUID) | Bit(unix.CAP_SETGID)
	// ChildModelI: the scan child's only capability under model (i).
	ChildModelI = Bit(unix.CAP_DAC_READ_SEARCH)
)

// CurrentCaps reads this thread's capability sets.
func CurrentCaps() (Caps, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return Caps{}, fmt.Errorf("capget: %w", err)
	}
	c := Caps{
		Effective:   uint64(data[0].Effective) | uint64(data[1].Effective)<<32,
		Permitted:   uint64(data[0].Permitted) | uint64(data[1].Permitted)<<32,
		Inheritable: uint64(data[0].Inheritable) | uint64(data[1].Inheritable)<<32,
	}
	for cap := 0; cap <= unix.CAP_LAST_CAP; cap++ {
		r, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(cap), 0, 0)
		if err == nil && r == 1 {
			c.Ambient |= Bit(cap)
		}
	}
	return c, nil
}

// LimitCaps reduces this thread's permitted and effective sets to allowed
// and its inheritable set to inheritable (both intersected with what it
// has). Dropping never needs a capability. The Go runtime applies capset
// per thread, so call this before starting goroutines that matter, and
// before spawning (os/exec forks from the calling thread).
func LimitCaps(allowed, inheritable uint64) error {
	cur, err := CurrentCaps()
	if err != nil {
		return err
	}
	prm := cur.Permitted & allowed
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: uint32(prm), Permitted: uint32(prm), Inheritable: uint32(cur.Inheritable & inheritable & prm)},
		{Effective: uint32(prm >> 32), Permitted: uint32(prm >> 32), Inheritable: uint32((cur.Inheritable & inheritable & prm) >> 32)},
	}
	// Capabilities are per thread: apply to every runtime thread (needs a
	// cgo-free binary, which the release build is).
	_, _, errno := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno == syscall.ENOTSUP {
		return unix.Capset(&hdr, &data[0])
	}
	if errno != 0 {
		return fmt.Errorf("capset: %w", errno)
	}
	return nil
}

// Names renders a mask as capability names, for logs.
func Names(mask uint64) string {
	names := map[int]string{
		unix.CAP_CHOWN: "CHOWN", unix.CAP_DAC_OVERRIDE: "DAC_OVERRIDE", unix.CAP_DAC_READ_SEARCH: "DAC_READ_SEARCH",
		unix.CAP_FOWNER: "FOWNER", unix.CAP_SETGID: "SETGID", unix.CAP_SETUID: "SETUID", unix.CAP_SETPCAP: "SETPCAP",
		unix.CAP_NET_ADMIN: "NET_ADMIN", unix.CAP_SYS_ADMIN: "SYS_ADMIN", unix.CAP_SYS_PTRACE: "SYS_PTRACE",
		unix.CAP_MKNOD: "MKNOD", unix.CAP_SYS_CHROOT: "SYS_CHROOT", unix.CAP_KILL: "KILL",
	}
	var out []string
	for c := 0; c <= unix.CAP_LAST_CAP; c++ {
		if mask&Bit(c) == 0 {
			continue
		}
		if n, ok := names[c]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("cap%d", c))
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ",")
}
