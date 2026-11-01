// Package token issues and verifies consistency tokens.
//
// A token names a store revision. Clients send it back to ask for a read that
// is at least as fresh as a write they made (the "new enemy" problem in the
// Zanzibar paper). Tokens are MACed so a client cannot invent a revision:
// a forged future revision could otherwise force reads to block or fail.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"github.com/laiwf94/authz/internal/authz/store"
)

// KeySize is the required key length in bytes.
const KeySize = 32

const (
	version = 1
	macSize = 16
	rawSize = 1 + 8 + macSize
)

// ErrInvalid is returned for any token that does not verify.
var ErrInvalid = errors.New("invalid consistency token")

// Issuer creates and verifies tokens with one secret key.
type Issuer struct{ key []byte }

// NewIssuer returns an issuer for a 32-byte key.
func NewIssuer(key []byte) (*Issuer, error) {
	if len(key) != KeySize {
		return nil, errors.New("token key must be 32 bytes")
	}
	return &Issuer{key: append([]byte(nil), key...)}, nil
}

// RandomKey returns a fresh key from the system's secure random source.
func RandomKey() ([]byte, error) {
	k := make([]byte, KeySize)
	_, err := rand.Read(k)
	return k, err
}

func (i *Issuer) mac(body []byte) []byte {
	m := hmac.New(sha256.New, i.key)
	m.Write(body)
	return m.Sum(nil)[:macSize]
}

// Encode returns the token for rev.
func (i *Issuer) Encode(rev store.Revision) string {
	raw := make([]byte, 0, rawSize)
	raw = append(raw, version)
	raw = binary.BigEndian.AppendUint64(raw, uint64(rev))
	raw = append(raw, i.mac(raw)...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// Decode verifies a token and returns its revision.
func (i *Issuer) Decode(tok string) (store.Revision, error) {
	if len(tok) > base64.RawURLEncoding.EncodedLen(rawSize) {
		return 0, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) != rawSize || raw[0] != version {
		return 0, ErrInvalid
	}
	if !hmac.Equal(raw[9:], i.mac(raw[:9])) {
		return 0, ErrInvalid
	}
	return store.Revision(binary.BigEndian.Uint64(raw[1:9])), nil
}
