package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Signed notes
//
// Checkpoints are signed notes, the format of the Go checksum database and of
// transparency logs' checkpoints (golang.org/x/mod/sumdb/note): UTF-8 text
// ending in a newline, a blank line, then one line per signature,
//
//	— <name> <base64(key hash || Ed25519 signature)>
//
// The key hash is the first four bytes, big-endian, of
// SHA-256(name || "\n" || 0x01 || public key), where 0x01 names Ed25519.
// Keys are written as text too:
//
//	PRIVATE+KEY+<name>+<key hash, 8 hex digits>+<base64(0x01 || seed)>   signer
//	<name>+<key hash, 8 hex digits>+<base64(0x01 || public key)>            verifier
//
// so a key made by any tool of that format (note.GenerateKey, the Go
// checksum database's tooling) can sign the audit log, and its checkpoints
// verify with any note verifier. This is a standard-library implementation;
// the module takes no dependency for it.

// algEd25519 is the note format's algorithm byte for Ed25519.
const algEd25519 = 1

// maxNoteSignatures bounds the signature lines OpenNote reads.
const maxNoteSignatures = 100

var (
	errMalformedNote = errors.New("malformed signed note")
	sigPrefix        = "— "
)

// Signer signs notes with an Ed25519 key under a name. Its String names the
// key and never shows it.
type Signer struct {
	name string
	hash uint32
	key  ed25519.PrivateKey
}

// Verifier checks notes signed by one Signer.
type Verifier struct {
	name string
	hash uint32
	key  ed25519.PublicKey
}

// validKeyName reports whether name may name a key: not empty, valid
// UTF-8, without spaces or '+'.
func validKeyName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

func keyHash(name string, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', algEd25519})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// ParseSigner reads a signer key: PRIVATE+KEY+<name>+<hash>+<key>. The
// errors never repeat the key.
func ParseSigner(s string) (*Signer, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "PRIVATE+KEY+")
	if !ok {
		return nil, errors.New(`audit: signing key must have the form PRIVATE+KEY+<name>+<hash>+<key> (see "authz audit keygen")`)
	}
	name, hash, key, err := splitKey(rest)
	if err != nil {
		return nil, fmt.Errorf("audit: signing key: %w", err)
	}
	if len(key) != 1+ed25519.SeedSize || key[0] != algEd25519 {
		return nil, errors.New("audit: signing key: not an Ed25519 key")
	}
	priv := ed25519.NewKeyFromSeed(key[1:])
	if keyHash(name, priv.Public().(ed25519.PublicKey)) != hash {
		return nil, errors.New("audit: signing key: the key hash does not match the name and key; it was mistyped or cut")
	}
	return &Signer{name: name, hash: hash, key: priv}, nil
}

// ParseVerifier reads a verifier key: <name>+<hash>+<key>.
func ParseVerifier(s string) (*Verifier, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "PRIVATE+KEY+") {
		return nil, errors.New("audit: that is a signing key; verify with the public key (authz audit keygen prints it)")
	}
	name, hash, key, err := splitKey(s)
	if err != nil {
		return nil, fmt.Errorf("audit: public key: %w", err)
	}
	if len(key) != 1+ed25519.PublicKeySize || key[0] != algEd25519 {
		return nil, errors.New("audit: public key: not an Ed25519 key")
	}
	pub := ed25519.PublicKey(key[1:])
	if keyHash(name, pub) != hash {
		return nil, errors.New("audit: public key: the key hash does not match the name and key; it was mistyped or cut")
	}
	return &Verifier{name: name, hash: hash, key: pub}, nil
}

// splitKey splits <name>+<hash>+<base64 key>.
func splitKey(s string) (name string, hash uint32, key []byte, err error) {
	name, rest, ok1 := strings.Cut(s, "+")
	hex8, b64, ok2 := strings.Cut(rest, "+")
	if !ok1 || !ok2 || !validKeyName(name) {
		return "", 0, nil, errors.New("must have the form <name>+<hash>+<key>, with a name without spaces or '+'")
	}
	h, err := strconv.ParseUint(hex8, 16, 32)
	if len(hex8) != 8 || err != nil {
		return "", 0, nil, errors.New("the key hash must be 8 hexadecimal digits")
	}
	key, err = base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) == 0 {
		return "", 0, nil, errors.New("the key is not valid base64")
	}
	return name, uint32(h), key, nil
}

// GenerateKey makes an Ed25519 key named name, returning its signer and
// verifier keys in text form.
func GenerateKey(rand io.Reader, name string) (signer, verifier string, err error) {
	if !validKeyName(name) {
		return "", "", errors.New("audit: a key name must not be empty or have spaces or '+'")
	}
	pub, priv, err := ed25519.GenerateKey(rand)
	if err != nil {
		return "", "", fmt.Errorf("audit: %w", err)
	}
	h := keyHash(name, pub)
	signer = fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, h, base64.StdEncoding.EncodeToString(append([]byte{algEd25519}, priv.Seed()...)))
	verifier = fmt.Sprintf("%s+%08x+%s", name, h, base64.StdEncoding.EncodeToString(append([]byte{algEd25519}, pub...)))
	return signer, verifier, nil
}

// Name is the key's name.
func (s *Signer) Name() string { return s.name }

// String names the key without showing it.
func (s *Signer) String() string { return fmt.Sprintf("audit signing key %s+%08x", s.name, s.hash) }

// GoString is String, so %#v does not show the key either.
func (s *Signer) GoString() string { return s.String() }

// Verifier returns the signer's public half.
func (s *Signer) Verifier() *Verifier {
	return &Verifier{name: s.name, hash: s.hash, key: s.key.Public().(ed25519.PublicKey)}
}

// Name is the key's name.
func (v *Verifier) Name() string { return v.name }

// String is the verifier key in text form, as ParseVerifier reads it.
func (v *Verifier) String() string {
	return fmt.Sprintf("%s+%08x+%s", v.name, v.hash, base64.StdEncoding.EncodeToString(append([]byte{algEd25519}, v.key...)))
}

// validNoteText reports whether text can be signed: valid UTF-8 without
// control characters other than newline, ending in a newline, and no blank
// line at its end (which would be read as the signature separator).
func validNoteText(text []byte) bool {
	return len(text) > 0 && text[len(text)-1] == '\n' && !bytes.HasSuffix(text, []byte("\n\n")) && noteChars(text)
}

// noteChars reports whether b is valid UTF-8 without control characters
// other than newline.
func noteChars(b []byte) bool {
	for i := 0; i < len(b); {
		r, n := utf8.DecodeRune(b[i:])
		if r < 0x20 && r != '\n' || r == utf8.RuneError && n == 1 {
			return false
		}
		i += n
	}
	return true
}

// SignNote returns text followed by a blank line and s's signature.
func SignNote(text []byte, s *Signer) ([]byte, error) {
	if !validNoteText(text) {
		return nil, errMalformedNote
	}
	sig := ed25519.Sign(s.key, text)
	raw := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(sig)), s.hash)
	raw = append(raw, sig...)
	out := make([]byte, 0, len(text)+len(s.name)+100)
	out = append(out, text...)
	out = append(out, '\n')
	out = append(out, sigPrefix...)
	out = append(out, s.name...)
	out = append(out, ' ')
	out = base64.StdEncoding.AppendEncode(out, raw)
	return append(out, '\n'), nil
}

// OpenNote checks that msg is a signed note carrying a valid signature by
// v and returns its text. Signatures by other keys are skipped; a
// signature by v's name and key hash that does not verify fails.
func OpenNote(msg []byte, v *Verifier) ([]byte, error) {
	if !noteChars(msg) {
		return nil, errMalformedNote
	}
	split := bytes.LastIndex(msg, []byte("\n\n"))
	if split < 0 {
		return nil, errMalformedNote
	}
	text, sigs := msg[:split+1], msg[split+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, errMalformedNote
	}
	verified := false
	for n := 0; len(sigs) > 0; n++ {
		if n == maxNoteSignatures {
			return nil, errMalformedNote
		}
		i := bytes.IndexByte(sigs, '\n')
		line := string(sigs[:i])
		sigs = sigs[i+1:]
		rest, ok := strings.CutPrefix(line, sigPrefix)
		if !ok {
			return nil, errMalformedNote
		}
		name, b64, _ := strings.Cut(rest, " ")
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || !validKeyName(name) || b64 == "" || len(raw) < 5 {
			return nil, errMalformedNote
		}
		if name != v.name || binary.BigEndian.Uint32(raw) != v.hash {
			continue
		}
		if !ed25519.Verify(v.key, text, raw[4:]) {
			return nil, fmt.Errorf("audit: the signature by %s does not verify: the note was changed after it was signed", v.name)
		}
		verified = true
	}
	if !verified {
		return nil, fmt.Errorf("audit: the note is not signed by %s+%08x", v.name, v.hash)
	}
	return text, nil
}
