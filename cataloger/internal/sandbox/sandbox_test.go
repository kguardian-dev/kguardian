package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The filter is installed in a re-executed copy of the test binary, never
// in the test process itself.
func TestMain(m *testing.M) {
	switch os.Getenv("KG_SANDBOX_CHILD") {
	case "seccomp":
		os.Exit(seccompChild())
	case "harden":
		os.Exit(hardenChild())
	}
	os.Exit(m.Run())
}

func reexec(t *testing.T, mode string, extra ...*os.File) []byte {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "KG_SANDBOX_CHILD="+mode)
	cmd.ExtraFiles = extra
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s child: %v\n%s", mode, err, stderr.String())
	}
	return out
}

func sys(nr uintptr, a ...uintptr) unix.Errno {
	var args [6]uintptr
	copy(args[:], a)
	r, _, e := unix.Syscall6(nr, args[0], args[1], args[2], args[3], args[4], args[5])
	if e == 0 && nr != unix.SYS_UNSHARE {
		// Close anything a successful call returned (sockets).
		if int(r) > 2 {
			_ = unix.Close(int(r))
		}
	}
	return e
}

func ptr(s string) uintptr {
	b, _ := unix.BytePtrFromString(s)
	return uintptr(unsafe.Pointer(b))
}

// seccompChild installs the filter and reports each probe's errno.
func seccompChild() int {
	// A thread that exists before the filter: TSYNC must cover it.
	pre := make(chan unix.Errno)
	ready := make(chan struct{})
	installed := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		close(ready)
		<-installed
		pre <- sys(unix.SYS_UNSHARE, 0)
	}()
	<-ready
	if err := InstallSeccomp(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	close(installed)
	res := map[string]int{}
	probe := func(name string, e unix.Errno) { res[name] = int(e) }
	probe("pre-existing thread unshare(0)", <-pre)
	probe("unshare(0)", sys(unix.SYS_UNSHARE, 0))
	probe("unshare(NEWUSER)", sys(unix.SYS_UNSHARE, unix.CLONE_NEWUSER))
	probe("setns", sys(unix.SYS_SETNS, ^uintptr(0), 0))
	probe("mount", sys(unix.SYS_MOUNT, ptr("none"), ptr("/tmp"), ptr("tmpfs"), 0, 0))
	probe("umount2", sys(unix.SYS_UMOUNT2, ptr("/tmp"), 0))
	probe("ptrace", sys(unix.SYS_PTRACE, unix.PTRACE_TRACEME))
	probe("process_vm_readv", sys(unix.SYS_PROCESS_VM_READV, uintptr(os.Getppid()), 0, 0, 0, 0, 0))
	probe("process_vm_writev", sys(unix.SYS_PROCESS_VM_WRITEV, uintptr(os.Getppid()), 0, 0, 0, 0, 0))
	probe("open_by_handle_at", sys(unix.SYS_OPEN_BY_HANDLE_AT, ^uintptr(0), 0, 0))
	probe("name_to_handle_at", sys(unix.SYS_NAME_TO_HANDLE_AT, ^uintptr(0), ptr("/"), 0, 0, 0))
	probe("bpf", sys(unix.SYS_BPF, 0, 0, 0))
	probe("perf_event_open", sys(unix.SYS_PERF_EVENT_OPEN, 0, 0, ^uintptr(0), ^uintptr(0), 0))
	probe("keyctl", sys(unix.SYS_KEYCTL, 0))
	probe("add_key", sys(unix.SYS_ADD_KEY, ptr("user"), ptr("k"), 0, 0, 0))
	probe("request_key", sys(unix.SYS_REQUEST_KEY, ptr("user"), ptr("k"), 0, 0))
	probe("chroot", sys(unix.SYS_CHROOT, ptr("/")))
	probe("pivot_root", sys(unix.SYS_PIVOT_ROOT, ptr("/"), ptr("/")))
	probe("kexec_load", sys(unix.SYS_KEXEC_LOAD, 0, 0, 0, 0))
	probe("kexec_file_load", sys(unix.SYS_KEXEC_FILE_LOAD, ^uintptr(0), ^uintptr(0), 0, 0, 0))
	probe("init_module", sys(unix.SYS_INIT_MODULE, 0, 0, 0))
	probe("finit_module", sys(unix.SYS_FINIT_MODULE, ^uintptr(0), 0, 0))
	probe("delete_module", sys(unix.SYS_DELETE_MODULE, ptr("x"), 0))
	probe("io_uring_setup", sys(unix.SYS_IO_URING_SETUP, 1, 0))
	probe("userfaultfd", sys(unix.SYS_USERFAULTFD, 0))
	probe("open_tree", sys(unix.SYS_OPEN_TREE, ^uintptr(0), ptr("/"), 0))
	probe("fsopen", sys(unix.SYS_FSOPEN, ptr("tmpfs"), 0))
	probe("pidfd_getfd", sys(unix.SYS_PIDFD_GETFD, ^uintptr(0), 0, 0))
	probe("execve", sys(unix.SYS_EXECVE, ptr("/bin/true"), 0, 0))
	probe("execveat", sys(unix.SYS_EXECVEAT, ^uintptr(0), ptr("/bin/true"), 0, 0, 0))
	// CLONE_THREAD without CLONE_SIGHAND is EINVAL from the kernel, so a
	// broken filter cannot actually fork here.
	probe("clone(NEWUSER)", sys(unix.SYS_CLONE, unix.CLONE_NEWUSER|unix.CLONE_THREAD))
	probe("clone3", sys(unix.SYS_CLONE3, 0, 0))
	probe("socket(AF_INET)", sys(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, 0))
	probe("socket(AF_INET6)", sys(unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_DGRAM, 0))
	probe("socket(AF_NETLINK)", sys(unix.SYS_SOCKET, unix.AF_NETLINK, unix.SOCK_RAW, 0))
	probe("socket(AF_PACKET)", sys(unix.SYS_SOCKET, unix.AF_PACKET, unix.SOCK_RAW, 0))
	probe("socketpair(AF_INET)", sys(unix.SYS_SOCKETPAIR, unix.AF_INET, unix.SOCK_STREAM, 0, 0))
	// Allowed.
	probe("socket(AF_UNIX)", sys(unix.SYS_SOCKET, unix.AF_UNIX, unix.SOCK_STREAM, 0))
	var sv [2]int32
	probe("socketpair(AF_UNIX)", sys(unix.SYS_SOCKETPAIR, unix.AF_UNIX, unix.SOCK_STREAM, 0, uintptr(unsafe.Pointer(&sv))))
	if _, err := os.ReadFile("/proc/self/status"); err != nil {
		probe("read file", err.(*os.PathError).Err.(unix.Errno))
	} else {
		probe("read file", 0)
	}
	nnp, _ := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	res["no_new_privs"] = nnp
	_ = json.NewEncoder(os.Stdout).Encode(res)
	return 0
}

func TestSeccompDenials(t *testing.T) {
	var got map[string]int
	if err := json.Unmarshal(reexec(t, "seccomp"), &got); err != nil {
		t.Fatal(err)
	}
	eperm := int(unix.EPERM)
	for name, want := range map[string]int{
		"pre-existing thread unshare(0)": eperm,
		"unshare(0)":                     eperm, "unshare(NEWUSER)": eperm, "setns": eperm, "mount": eperm,
		"umount2": eperm, "ptrace": eperm, "process_vm_readv": eperm, "process_vm_writev": eperm,
		"open_by_handle_at": eperm, "name_to_handle_at": eperm, "bpf": eperm, "perf_event_open": eperm,
		"keyctl": eperm, "add_key": eperm, "request_key": eperm, "chroot": eperm, "pivot_root": eperm,
		"kexec_load": eperm, "kexec_file_load": eperm, "init_module": eperm, "finit_module": eperm,
		"delete_module": eperm, "io_uring_setup": eperm, "userfaultfd": eperm, "open_tree": eperm,
		"fsopen": eperm, "pidfd_getfd": eperm, "execve": eperm, "execveat": eperm, "clone(NEWUSER)": eperm,
		"clone3":          int(unix.ENOSYS),
		"socket(AF_INET)": eperm, "socket(AF_INET6)": eperm, "socket(AF_NETLINK)": eperm,
		"socket(AF_PACKET)": eperm, "socketpair(AF_INET)": eperm,
		"socket(AF_UNIX)": 0, "socketpair(AF_UNIX)": 0, "read file": 0, "no_new_privs": 1,
	} {
		v, ok := got[name]
		if !ok {
			t.Errorf("%s: not probed", name)
			continue
		}
		if v != want {
			t.Errorf("%s: errno %d (%v), want %d (%v)", name, v, unix.Errno(v), want, unix.Errno(want))
		}
	}
}

// hardenChild applies Harden with fds 3 and 4 open and fd 5 extra, and
// reports what is left.
func hardenChild() int {
	if err := Harden(Limits{KeepFDs: 5, MemoryLimit: 64 << 20, MaxFileSize: 1 << 20}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fds, _ := OpenFDs()
	var nofile, core, fsize unix.Rlimit
	_ = unix.Getrlimit(unix.RLIMIT_NOFILE, &nofile)
	_ = unix.Getrlimit(unix.RLIMIT_CORE, &core)
	_ = unix.Getrlimit(unix.RLIMIT_FSIZE, &fsize)
	nice, _ := unix.Getpriority(unix.PRIO_PROCESS, 0)
	ioprio, _, _ := unix.Syscall(unix.SYS_IOPRIO_GET, ioprioWhoProcess, 0, 0)
	// A write past RLIMIT_FSIZE must fail with EFBIG, not kill us.
	f, _ := os.CreateTemp("", "fsize")
	_, werr := f.Write(make([]byte, 2<<20))
	_ = f.Close()
	_ = os.Remove(f.Name())
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"fds": fds, "nofile": nofile.Cur, "core": core.Cur, "fsize": fsize.Cur, "nice": nice,
		"ioprio_class": ioprio >> ioprioClassShift, "gomaxprocs": runtime.GOMAXPROCS(0),
		"efbig": werr != nil && strings.Contains(werr.Error(), "file too large"),
	})
	return 0
}

func TestHarden(t *testing.T) {
	var files []*os.File
	for range 3 {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		files = append(files, f)
	}
	var got struct {
		FDs         []int  `json:"fds"`
		Nofile      uint64 `json:"nofile"`
		Core        uint64 `json:"core"`
		Fsize       uint64 `json:"fsize"`
		Nice        int    `json:"nice"`
		IoprioClass int    `json:"ioprio_class"`
		GOMAXPROCS  int    `json:"gomaxprocs"`
		EFBIG       bool   `json:"efbig"`
	}
	if err := json.Unmarshal(reexec(t, "harden", files...), &got); err != nil {
		t.Fatal(err)
	}
	for _, fd := range got.FDs {
		if fd > 4 {
			t.Errorf("fd %d survived close_range (open: %v)", fd, got.FDs)
		}
	}
	// getpriority(2) returns 20-nice through the raw syscall; x/sys
	// returns the raw value.
	if got.Nofile != 4096 || got.Core != 0 || got.Fsize != 1<<20 || got.GOMAXPROCS != 1 || !got.EFBIG ||
		got.IoprioClass != ioprioClassIdle || (got.Nice != 19 && got.Nice != 1) {
		t.Errorf("limits %+v", got)
	}
}

func TestFilterShape(t *testing.T) {
	f := Filter()
	if len(f) > 4096 || len(f) < 50 {
		t.Fatalf("filter has %d instructions", len(f))
	}
	if f[len(f)-1].Code != retK || f[len(f)-1].K != retAllow {
		t.Error("filter must end in allow")
	}
}
