package audit

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClean(t *testing.T) {
	for _, c := range []struct {
		in   string
		max  int
		want string
	}{
		{"alice", 512, "alice"},
		{"", 512, ""},
		{"a\nb", 512, "a�b"},
		{"a\x00b\x7f", 512, "a�b�"},
		{"a\xffb", 512, "a�b"},
		{"abcdef", 4, "abcd"},
		{"abé", 3, "ab"}, // é is two bytes and does not fit
		{"éé", 4, "éé"},  // exactly fits
		{"x\ty", 2, "x"}, // U+FFFD is three bytes
	} {
		got := Clean(c.in, c.max)
		if got != c.want {
			t.Errorf("Clean(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
		if err := checkText("f", got, c.max); err != nil {
			t.Errorf("Clean(%q, %d) = %q fails the envelope check: %v", c.in, c.max, got, err)
		}
	}
	long := strings.Repeat("é", 400) + "\x01"
	got := Clean(long, MaxEnvelopeBytes)
	if len(got) > MaxEnvelopeBytes || !utf8.ValidString(got) {
		t.Fatalf("Clean of a long value: %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
	if err := (Envelope{Actor: got, Subject: Clean("s\r\n", MaxEnvelopeBytes)}).Check(); err != nil {
		t.Fatal(err)
	}
}
