package rootfs

import (
	"bytes"
	"strings"
	"testing"
	"testing/iotest"
)

func TestHasMarker(t *testing.T) {
	m := dotnetBundleSignature
	at := func(size, off int) []byte {
		b := make([]byte, size)
		if off >= 0 {
			copy(b[off:], m)
		}
		return b
	}
	for name, tc := range map[string]struct {
		data []byte
		want bool
	}{
		"empty":            {nil, false},
		"shorter":          {m[:10], false},
		"exact":            {m, true},
		"none":             {at(3<<20, -1), false},
		"start":            {at(3<<20, 0), true},
		"end":              {at(3<<20, 3<<20-len(m)), true},
		"across a read":    {at(3<<20, 1<<20-5), true},
		"across the carry": {at(3<<20, 2<<20+len(m)-1-7), true},
		"cut at the end":   {at(3<<20, -1)[:3<<20-1], false},
	} {
		if got, err := hasMarker(bytes.NewReader(tc.data), m); err != nil || got != tc.want {
			t.Errorf("%s: %v %v, want %v", name, got, err, tc.want)
		}
		// One byte at a time: every read boundary.
		if len(tc.data) < 1<<16 {
			got, err := hasMarker(iotest.OneByteReader(bytes.NewReader(tc.data)), m)
			if err != nil || got != tc.want {
				t.Errorf("%s/bytewise: %v %v, want %v", name, got, err, tc.want)
			}
		}
	}
	if _, err := hasMarker(iotest.ErrReader(iotest.ErrTimeout), m); err == nil {
		t.Error("read error not reported")
	}
	if got, _ := hasMarker(strings.NewReader("xx"+string(m[:31])), m); got {
		t.Error("a partial marker matched")
	}
}
