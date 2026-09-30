package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/sys/unix"
)

// ErrFrameTooLarge is a length prefix above the direction's limit.
var ErrFrameTooLarge = errors.New("frame exceeds size limit")

// FD-passing failures a request can carry.
var (
	// ErrFDStripped: MSG_CTRUNC with no fd, i.e. an LSM refused the fd in
	// transit (lsm_denied).
	ErrFDStripped = errors.New("fd stripped in transit (MSG_CTRUNC)")
	// ErrBadRights: more than one fd, or a control message other than
	// SCM_RIGHTS (bad_request). Every received fd is closed.
	ErrBadRights = errors.New("expected exactly one SCM_RIGHTS fd")
)

// WriteFrame writes one length-prefixed frame.
func WriteFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(append(hdr[:], payload...)); err != nil {
		return err
	}
	return nil
}

// ReadFrame reads one frame of at most max payload bytes.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	return readPayload(r, hdr, nil, max)
}

func readPayload(r io.Reader, hdr [4]byte, have []byte, max int) ([]byte, error) {
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 2 || n > max {
		return nil, fmt.Errorf("%w: %d bytes (limit %d)", ErrFrameTooLarge, n, max)
	}
	if len(have) > n {
		return nil, errors.New("trailing data after frame")
	}
	buf := make([]byte, n)
	copy(buf, have)
	if _, err := io.ReadFull(r, buf[len(have):]); err != nil {
		return nil, err
	}
	return buf, nil
}

// WriteJSON frames v.
func WriteJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return WriteFrame(w, b)
}

// SendRequest sends req with fd attached (fd < 0: none, for ping) in one
// sendmsg, as the Controller must.
func SendRequest(c *net.UnixConn, req *Request, fd int) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if len(b) > MaxRequestBytes {
		return fmt.Errorf("%w: request is %d bytes", ErrFrameTooLarge, len(b))
	}
	frame := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(frame, uint32(len(b)))
	copy(frame[4:], b)
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	n, _, err := c.WriteMsgUnix(frame, oob, nil)
	if err != nil {
		return err
	}
	if n < len(frame) {
		_, err = c.Write(frame[n:])
	}
	return err
}

// RecvRequest reads one request frame and the fd that came with it
// (-1 if none). The returned error wraps ErrFDStripped, ErrBadRights,
// ErrFrameTooLarge or a JSON/transport error; any fd received alongside
// an error is already closed.
func RecvRequest(c *net.UnixConn) (*Request, int, error) {
	buf := make([]byte, 4+MaxRequestBytes)
	oob := make([]byte, unix.CmsgSpace(8*4))
	n, oobn, flags, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, -1, err
	}
	fd, rightsErr := parseRights(oob[:oobn], flags)
	closeFD := func() {
		if fd >= 0 {
			_ = unix.Close(fd)
			fd = -1
		}
	}
	if rightsErr != nil {
		closeFD()
		return nil, -1, rightsErr
	}
	if n == 0 {
		closeFD()
		return nil, -1, io.EOF
	}
	var hdr [4]byte
	got := buf[:n]
	if len(got) < 4 {
		copy(hdr[:], got)
		if _, err := io.ReadFull(c, hdr[len(got):]); err != nil {
			closeFD()
			return nil, -1, err
		}
		got = nil
	} else {
		copy(hdr[:], got[:4])
		got = got[4:]
	}
	payload, err := readPayload(c, hdr, got, MaxRequestBytes)
	if err != nil {
		closeFD()
		return nil, -1, err
	}
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		closeFD()
		return nil, -1, fmt.Errorf("request JSON: %w", err)
	}
	return &req, fd, nil
}

func parseRights(oob []byte, flags int) (int, error) {
	fd := -1
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return -1, fmt.Errorf("%w: %v", ErrBadRights, err)
	}
	var all []int
	bad := false
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_RIGHTS {
			bad = true
			continue
		}
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			bad = true
			continue
		}
		all = append(all, fds...)
	}
	if flags&unix.MSG_CTRUNC != 0 {
		for _, f := range all {
			_ = unix.Close(f)
		}
		if len(all) == 0 {
			return -1, ErrFDStripped
		}
		return -1, fmt.Errorf("%w: control data truncated", ErrBadRights)
	}
	if bad || len(all) > 1 {
		for _, f := range all {
			_ = unix.Close(f)
		}
		return -1, ErrBadRights
	}
	if len(all) == 1 {
		fd = all[0]
	}
	return fd, nil
}

// ReadResponse reads and decodes one response frame (the Controller side,
// and the tests' fake Controller).
func ReadResponse(r io.Reader, max int) (*Response, error) {
	b, err := ReadFrame(r, max)
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, fmt.Errorf("response JSON: %w", err)
	}
	return &resp, nil
}
