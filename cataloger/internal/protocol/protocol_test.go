package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func pair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "sock")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c.(*net.UnixConn)
	}
	return conn(fds[0]), conn(fds[1])
}

func tmpDirFD(t *testing.T) int {
	t.Helper()
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func scanReq() *Request {
	return &Request{ProtocolVersion: Version, Op: OpScan, ScanID: "s-1", Epoch: 7, ContainerStartUnixNanos: 1,
		Submounts: []string{"/proc", "/etc/hosts"}, Budgets: Budgets{MaxFiles: 10}}
}

func TestRequestRoundTripWithFD(t *testing.T) {
	a, b := pair(t)
	dir := tmpDirFD(t)
	if err := SendRequest(a, scanReq(), dir); err != nil {
		t.Fatal(err)
	}
	req, fd, err := RecvRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if req.ScanID != "s-1" || req.Epoch != 7 || len(req.Submounts) != 2 || req.Budgets.MaxFiles != 10 {
		t.Errorf("req %+v", req)
	}
	var a1, a2 unix.Stat_t
	_ = unix.Fstat(dir, &a1)
	_ = unix.Fstat(fd, &a2)
	if a1.Ino != a2.Ino || a1.Dev != a2.Dev {
		t.Error("received fd is not the sent directory")
	}
	flags, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if flags&unix.FD_CLOEXEC == 0 {
		t.Error("received fd lacks FD_CLOEXEC")
	}
}

func TestRequestWithoutFD(t *testing.T) {
	a, b := pair(t)
	req := &Request{ProtocolVersion: Version, Op: OpPing, ScanID: "p"}
	if err := SendRequest(a, req, -1); err != nil {
		t.Fatal(err)
	}
	got, fd, err := RecvRequest(b)
	if err != nil || fd != -1 || got.Op != OpPing {
		t.Fatalf("got %+v fd %d err %v", got, fd, err)
	}
}

func TestTwoFDsRejectedAndClosed(t *testing.T) {
	a, b := pair(t)
	d1, d2 := tmpDirFD(t), tmpDirFD(t)
	body, _ := json.Marshal(scanReq())
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	frame = append(frame, body...)
	if _, _, err := a.WriteMsgUnix(frame, unix.UnixRights(d1, d2), nil); err != nil {
		t.Fatal(err)
	}
	before := countFDs(t)
	_, fd, err := RecvRequest(b)
	if !errors.Is(err, ErrBadRights) || fd != -1 {
		t.Fatalf("err %v fd %d", err, fd)
	}
	if after := countFDs(t); after > before {
		t.Errorf("leaked %d fds", after-before)
	}
}

func countFDs(t *testing.T) int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

func TestFrameSplitAcrossReads(t *testing.T) {
	a, b := pair(t)
	dir := tmpDirFD(t)
	body, _ := json.Marshal(scanReq())
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	frame = append(frame, body...)
	// The fd rides on the first 3 bytes; the rest arrives separately.
	if _, _, err := a.WriteMsgUnix(frame[:3], unix.UnixRights(dir), nil); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = a.Write(frame[3:]) }()
	req, fd, err := RecvRequest(b)
	if err != nil || fd < 0 || req.ScanID != "s-1" {
		t.Fatalf("req %+v fd %d err %v", req, fd, err)
	}
	_ = unix.Close(fd)
}

func TestOversizeFrameRefusedWithoutReading(t *testing.T) {
	a, b := pair(t)
	hdr := binary.BigEndian.AppendUint32(nil, MaxRequestBytes+1)
	if _, err := a.Write(hdr); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecvRequest(b); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(binary.BigEndian.AppendUint32(nil, 1)), 10); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("a 1-byte frame: %v", err)
	}
}

func TestCtruncWithoutFDIsStripped(t *testing.T) {
	if _, err := parseRights(nil, unix.MSG_CTRUNC); !errors.Is(err, ErrFDStripped) {
		t.Fatalf("got %v", err)
	}
	if fd, err := parseRights(nil, 0); err != nil || fd != -1 {
		t.Fatalf("no control data: fd %d err %v", fd, err)
	}
}

func TestValidate(t *testing.T) {
	ok := scanReq()
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(r *Request){
		ReasonUnsupportedProtocol: func(r *Request) { r.ProtocolVersion = 2 },
		ReasonBadRequest + " id":  func(r *Request) { r.ScanID = "has space" },
		ReasonBadRequest + " op":  func(r *Request) { r.Op = "exec" },
		ReasonBadRequest + " sub": func(r *Request) { r.Submounts = []string{"relative"} },
		ReasonBadRequest + " dot": func(r *Request) { r.Submounts = []string{"/a/../b"} },
		ReasonBadRequest + " neg": func(r *Request) { r.Budgets.MaxFiles = -1 },
		ReasonBadRequest + " pro": func(r *Request) { r.Profile = "everything" },
		ReasonBadRequest + " len": func(r *Request) { r.ScanID = strings.Repeat("a", 129) },
	}
	for name, mut := range cases {
		r := *scanReq()
		mut(&r)
		err := r.Validate()
		var re *RequestError
		if !errors.As(err, &re) || re.Reason != strings.Fields(name)[0] {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestBudgetsEffective(t *testing.T) {
	e := Budgets{MaxFiles: 1 << 40, MaxComponents: 5, ScanTimeoutMS: 0}.Effective()
	if e.MaxFiles != CeilingBudgets.MaxFiles || e.MaxComponents != 5 || e.ScanTimeoutMS != DefaultBudgets.ScanTimeoutMS ||
		e.MaxResponseBytes != DefaultBudgets.MaxResponseBytes {
		t.Errorf("%+v", e)
	}
}

// The response's component fields must decode as the broker's
// ImageSBOM v1 WireComponent (broker/src/supplychain.rs): same JSON names.
func TestComponentFieldNamesMatchBroker(t *testing.T) {
	c := Component{Name: "n", Version: "v", PURL: "p", Type: "t", Class: "os-pkgs", SrcName: "s", SrcVersion: "sv",
		Licenses: []string{"MIT"}, FilePaths: []string{"/x"}, FilesTruncated: true, InterpretedContent: true}
	b, _ := json.Marshal(c)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	broker := []string{"name", "version", "purl", "type", "class", "src_name", "src_version", "licenses", "file_paths"}
	for _, k := range broker {
		if _, ok := m[k]; !ok {
			t.Errorf("missing broker field %q", k)
		}
	}
	for k := range m {
		switch k {
		case "files_truncated", "interpreted_content":
		default:
			found := false
			for _, b := range broker {
				found = found || b == k
			}
			if !found {
				t.Errorf("field %q is neither a broker WireComponent field nor a documented flag", k)
			}
		}
	}
}
