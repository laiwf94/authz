package jose

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// HS256 is the one symmetric JWS algorithm this package implements. It is
// not in SupportedAlgorithms and Verify never accepts it: a token verified
// with a shared secret goes through VerifyHMAC, so a public key can never be
// used as an HMAC secret (RFC 8725 section 2.1).
const HS256 = "HS256"

// MinHMACKeyBytes is the shortest HS256 secret accepted, the size of the
// hash output (RFC 7518 section 3.2).
const MinHMACKeyBytes = 32

// ErrHeader reports a protected header with members a strict caller does not
// accept.
var ErrHeader = errors.New("jose: unexpected header member")

// VerifyHMAC checks an HS256 signature with secret. The token must say
// HS256: the header cannot pick another algorithm.
func (t *Token) VerifyHMAC(secret []byte) error {
	if t.Header.Alg != HS256 {
		return fmt.Errorf("%w: %q", ErrAlgorithm, t.Header.Alg)
	}
	if len(secret) < MinHMACKeyBytes {
		return fmt.Errorf("%w: HS256 secret shorter than %d bytes", ErrKeyMismatch, MinHMACKeyBytes)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(t.signingInput)
	if !hmac.Equal(t.signature, mac.Sum(nil)) {
		return ErrSignature
	}
	return nil
}

// StrictHeader fails with ErrHeader when the protected header has members
// other than alg, kid, typ and crit. Parse ignores such members, since keys
// never come from the token; issuers of tokens that must look exactly like
// their own (agent tokens) refuse them instead.
func (t *Token) StrictHeader() error {
	if t.extraHeader {
		return ErrHeader
	}
	return nil
}

// SignHMAC serializes claims and returns a compact HS256 JWS with typ "JWT"
// and the given kid.
func SignHMAC(kid string, secret []byte, claims any) (string, error) {
	if len(secret) < MinHMACKeyBytes {
		return "", fmt.Errorf("%w: HS256 secret shorter than %d bytes", ErrKeyMismatch, MinHMACKeyBytes)
	}
	hb, _ := json.Marshal(Header{Alg: HS256, Kid: kid, Typ: "JWT"})
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
