package seal

import (
	"errors"
	"testing"
)

// A sealed value with a CR or LF inserted is a different string and must
// not open, though Go's base64 decoders skip both (#237).
func TestOpenRefusesLineBreaks(t *testing.T) {
	kr, err := New([][]byte{RandomKey()})
	if err != nil {
		t.Fatal(err)
	}
	s := kr.Seal("p", []byte("hello"))
	if b, err := kr.Open("p", s); err != nil || string(b) != "hello" {
		t.Fatalf("Open = %q, %v", b, err)
	}
	for _, br := range []string{"\n", "\r"} {
		for _, i := range []int{1, len(s) / 2, len(s) - 1} {
			if _, err := kr.Open("p", s[:i]+br+s[i:]); !errors.Is(err, ErrInvalid) {
				t.Errorf("%q at %d: Open = %v, want ErrInvalid", br, i, err)
			}
		}
	}
}
