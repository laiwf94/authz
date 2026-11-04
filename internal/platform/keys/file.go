package keys

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileVersion is the ring file format version Save writes and Load reads.
const FileVersion = 1

// MaxFileBytes bounds a ring file or key file.
const MaxFileBytes = 1 << 20

type fileKey struct {
	Kid     string    `json:"kid"`
	Alg     Alg       `json:"alg"`
	Created time.Time `json:"created"`
	Private string    `json:"private,omitempty"` // PKCS #8, base64
	Secret  string    `json:"secret,omitempty"`  // base64url
}

type fileRetired struct {
	Key   fileKey    `json:"key"`
	Until *time.Time `json:"until,omitempty"`
}

type fileRing struct {
	Name        string        `json:"name"`
	Alg         Alg           `json:"alg"`
	RotateEvery string        `json:"rotate_every,omitempty"`
	Overlap     string        `json:"overlap,omitempty"`
	Activated   time.Time     `json:"activated"`
	Current     fileKey       `json:"current"`
	Next        *fileKey      `json:"next,omitempty"`
	Previous    []fileRetired `json:"previous,omitempty"`
}

type file struct {
	Version int        `json:"version"`
	Rings   []fileRing `json:"rings"`
}

// Marshal encodes the set as a ring file. It holds private keys: store it
// like any other secret.
func (s *Set) Marshal() ([]byte, error) {
	f := file{Version: FileVersion, Rings: []fileRing{}}
	for _, name := range s.Names() {
		r := s.Ring(name)
		st := r.Snapshot()
		fr := fileRing{Name: name, Alg: r.alg, Activated: st.Activated, Current: encodeKey(st.Current)}
		if p := r.policy; p.RotateEvery > 0 || p.Overlap > 0 {
			fr.RotateEvery, fr.Overlap = p.RotateEvery.String(), p.Overlap.String()
		}
		if st.Next != nil {
			n := encodeKey(st.Next)
			fr.Next = &n
		}
		for _, p := range st.Previous {
			fp := fileRetired{Key: encodeKey(p.Key)}
			if !p.Until.IsZero() {
				u := p.Until
				fp.Until = &u
			}
			fr.Previous = append(fr.Previous, fp)
		}
		f.Rings = append(f.Rings, fr)
	}
	return json.MarshalIndent(f, "", "  ")
}

func encodeKey(k *Key) fileKey {
	fk := fileKey{Kid: k.id, Alg: k.alg, Created: k.created}
	if k.alg.Symmetric() {
		fk.Secret = b64(k.secret)
	} else {
		der, _ := x509.MarshalPKCS8PrivateKey(k.Signer()) // every key type here marshals
		fk.Private = base64.StdEncoding.EncodeToString(der)
	}
	return fk
}

// Unmarshal decodes a ring file. Unknown members, a version other than
// FileVersion, a key whose id doesn't match its material, or a ring that
// Restore refuses all fail the whole file.
func Unmarshal(b []byte) (*Set, error) {
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("keys: ring file larger than %d bytes", MaxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f file
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("keys: ring file: %w", err)
	}
	if dec.More() {
		return nil, errors.New("keys: ring file: trailing data")
	}
	if f.Version != FileVersion {
		return nil, fmt.Errorf("keys: ring file version %d; this build reads version %d", f.Version, FileVersion)
	}
	s := NewSet()
	for i, fr := range f.Rings {
		r, err := decodeRing(fr)
		if err != nil {
			return nil, fmt.Errorf("keys: ring file: rings[%d] (%s): %w", i, fr.Name, err)
		}
		if err := s.Add(fr.Name, r); err != nil {
			return nil, fmt.Errorf("keys: ring file: rings[%d]: %w", i, err)
		}
	}
	return s, nil
}

func decodeRing(fr fileRing) (*Ring, error) {
	var p Policy
	var err error
	if fr.RotateEvery != "" {
		if p.RotateEvery, err = time.ParseDuration(fr.RotateEvery); err != nil {
			return nil, fmt.Errorf("rotate_every: %w", err)
		}
	}
	if fr.Overlap != "" {
		if p.Overlap, err = time.ParseDuration(fr.Overlap); err != nil {
			return nil, fmt.Errorf("overlap: %w", err)
		}
	}
	st := Snapshot{Activated: fr.Activated}
	if st.Current, err = decodeKey(fr.Current); err != nil {
		return nil, fmt.Errorf("current: %w", err)
	}
	if fr.Next != nil {
		if st.Next, err = decodeKey(*fr.Next); err != nil {
			return nil, fmt.Errorf("next: %w", err)
		}
	}
	for i, fp := range fr.Previous {
		k, err := decodeKey(fp.Key)
		if err != nil {
			return nil, fmt.Errorf("previous[%d]: %w", i, err)
		}
		r := Retired{Key: k}
		if fp.Until != nil {
			r.Until = fp.Until.UTC()
		}
		st.Previous = append(st.Previous, r)
	}
	return Restore(fr.Alg, p, st)
}

func decodeKey(fk fileKey) (*Key, error) {
	if !fk.Alg.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrAlg, fk.Alg)
	}
	if fk.Alg.Symmetric() {
		if fk.Private != "" {
			return nil, fmt.Errorf("%w: %s key %s has a private key", ErrKey, fk.Alg, fk.Kid)
		}
		sec, err := base64.RawURLEncoding.Strict().DecodeString(fk.Secret)
		if err != nil {
			return nil, fmt.Errorf("%w: secret of %s: %v", ErrKey, fk.Kid, err)
		}
		if fk.Kid == "" {
			return nil, fmt.Errorf("%w: key without kid", ErrKey)
		}
		return FromSecret(fk.Alg, fk.Kid, sec, fk.Created)
	}
	if fk.Secret != "" {
		return nil, fmt.Errorf("%w: %s key %s has a secret", ErrKey, fk.Alg, fk.Kid)
	}
	der, err := base64.StdEncoding.Strict().DecodeString(fk.Private)
	if err != nil {
		return nil, fmt.Errorf("%w: private key of %s: %v", ErrKey, fk.Kid, err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: private key of %s: %v", ErrKey, fk.Kid, err)
	}
	signer, _ := priv.(crypto.Signer) // every PKCS #8 key type Go parses is one
	k, err := FromSigner(signer, fk.Created)
	if err != nil {
		return nil, err
	}
	if k.alg != fk.Alg {
		return nil, fmt.Errorf("%w: key %s is %s, the file says %s", ErrKey, fk.Kid, k.alg, fk.Alg)
	}
	if k.id != fk.Kid {
		return nil, fmt.Errorf("%w: key %s has thumbprint %s", ErrKey, fk.Kid, k.id)
	}
	return k, nil
}

// Save writes the set to path atomically with mode 0600: a temporary file
// in the same directory, synced, then renamed over path, so a reader or a
// crash never sees half a file.
func (s *Set) Save(path string) error {
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Load reads a ring file written by Save.
func Load(path string) (*Set, error) {
	b, err := readLimited(path)
	if err != nil {
		return nil, err
	}
	s, err := Unmarshal(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, MaxFileBytes)
	}
	return b, nil
}

// ReadKeyFile reads one key in the formats the earlier binaries used:
//
//   - a PEM private key, PKCS #8 ("PRIVATE KEY"), SEC 1 ("EC PRIVATE KEY")
//     or PKCS #1 ("RSA PRIVATE KEY"), as WICKET_SIGNING_KEYS and the SAML
//     sp_key_file name; the first private key block counts, so a file may
//     also hold certificates;
//   - 64 hex characters, as `authz gateway genkey` prints for
//     WICKET_COOKIE_KEYS and as GRANTD_TOKEN_KEY holds, for HS256 and
//     A256GCM.
//
// want, when not empty, is the algorithm the key must have. The modification
// time stamps the key's creation.
func ReadKeyFile(path string, want Alg) (*Key, error) {
	b, err := readLimited(path)
	if err != nil {
		return nil, err
	}
	var created time.Time
	if fi, err := os.Stat(path); err == nil {
		created = fi.ModTime()
	}
	k, err := parseKeyFile(b, want, created)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

func parseKeyFile(b []byte, want Alg, created time.Time) (*Key, error) {
	if want != "" && !want.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrAlg, want)
	}
	if bytes.Contains(b, []byte("-----BEGIN ")) {
		k, err := parsePEM(b, created)
		if err != nil {
			return nil, err
		}
		if want != "" && k.alg != want {
			return nil, fmt.Errorf("%w: %s key, want %s", ErrRingAlg, k.alg, want)
		}
		return k, nil
	}
	if want == "" || !want.Symmetric() {
		return nil, fmt.Errorf("%w: no PEM private key", ErrKey)
	}
	sec, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%w: want a PEM private key or hex: %v", ErrKey, err)
	}
	return FromSecret(want, "", sec, created)
}

func parsePEM(b []byte, created time.Time) (*Key, error) {
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			return nil, fmt.Errorf("%w: no PEM private key block", ErrKey)
		}
		var priv any
		var err error
		switch blk.Type {
		case "PRIVATE KEY":
			priv, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
		case "EC PRIVATE KEY":
			priv, err = x509.ParseECPrivateKey(blk.Bytes)
		case "RSA PRIVATE KEY":
			priv, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrKey, blk.Type, err)
		}
		if s, ok := priv.(crypto.Signer); ok {
			return FromSigner(s, created)
		}
		return nil, fmt.Errorf("%w: unsupported private key type %T", ErrKey, priv)
	}
}

// ParseSecretList reads the comma-separated secret lists of the earlier
// environment variables, first entry current:
//
//   - "hex,hex": WICKET_COOKIE_KEYS (A256GCM) and GRANTD_TOKEN_KEY (HS256),
//     each 64 hex characters, key ids derived from the secrets;
//   - "kid=hex,kid=hex": TOOLGATE_SIGNING_KEYS (HS256), key ids kept.
//
// Every key is stamped with created.
func ParseSecretList(alg Alg, v string, created time.Time) ([]*Key, error) {
	if !alg.Symmetric() {
		return nil, fmt.Errorf("%w: %q is not a secret-key algorithm", ErrAlg, alg)
	}
	var out []*Key
	seen := map[string]bool{}
	for i, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kid, hx, named := strings.Cut(part, "=")
		if !named {
			kid, hx = "", part
		}
		sec, err := hex.DecodeString(hx)
		if err != nil || len(sec) != SealKeyBytes {
			return nil, fmt.Errorf("%w: entry %d must be 64 hex characters, optionally after kid=", ErrKey, i)
		}
		k, err := FromSecret(alg, kid, sec, created)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if seen[k.id] {
			return nil, fmt.Errorf("%w: entry %d repeats key id %s", ErrKey, i, k.id)
		}
		seen[k.id] = true
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no keys", ErrKey)
	}
	return out, nil
}

// Configured makes a ring from configured keys, first one current and the
// rest retired with no expiry, as seal.New and the agent gateway treat their
// key lists.
func Configured(p Policy, activated time.Time, ks ...*Key) (*Ring, error) {
	if len(ks) == 0 {
		return nil, errors.New("keys: no keys")
	}
	st := Snapshot{Current: ks[0], Activated: activated}
	for _, k := range ks[1:] {
		st.Previous = append(st.Previous, Retired{Key: k})
	}
	return Restore(ks[0].alg, p, st)
}
