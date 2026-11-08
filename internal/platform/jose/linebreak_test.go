package jose

import (
	"errors"
	"strings"
	"testing"
)

// A CR or LF anywhere in a part makes a different string, so it must not
// parse to a token that verifies, though Go's base64 decoders skip both
// (#237).
func TestLineBreakInPartRefused(t *testing.T) {
	tok, err := SignHMAC("k1", hmacKey, map[string]any{"sub": "a"})
	if err != nil {
		t.Fatal(err)
	}
	if p, err := Parse(tok); err != nil || p.VerifyHMAC(hmacKey) != nil {
		t.Fatalf("the token itself: %v", err)
	}
	for _, br := range []string{"\n", "\r", "\r\n"} {
		for i := 1; i < len(tok); i++ {
			if tok[i-1] == '.' || tok[i] == '.' {
				continue
			}
			bad := tok[:i] + br + tok[i:]
			if _, err := Parse(bad); !errors.Is(err, ErrMalformed) {
				t.Fatalf("%q at %d: Parse = %v, want ErrMalformed", br, i, err)
			}
		}
	}
}

func TestLineBreakInKeyMemberRefused(t *testing.T) {
	if _, err := decodeBigInt("AQAB"); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeBigInt("AQ\nAB"); err == nil {
		t.Error("decodeBigInt accepted a line break")
	}
	x := strings.Repeat("A", 43)
	if _, err := decodeFixed(x, 32); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeFixed(x[:20]+"\r\n"+x[20:], 32); err == nil {
		t.Error("decodeFixed accepted a line break")
	}
}
