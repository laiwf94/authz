package keys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fullSet(t *testing.T) *Set {
	t.Helper()
	s := NewSet()
	up := newRing(t, ES256, hourly)
	_ = up.Rotate(t0.Add(time.Hour))
	sess := mustConfigured(t, mustGen(t, A256GCM), mustGen(t, A256GCM))
	named, _ := FromSecret(HS256, "k1", bytes.Repeat([]byte{1}, 32), t0)
	agent := mustConfigured(t, named)
	ed := newRing(t, EdDSA, Policy{})
	_ = ed.Rotate(t0)
	rs, _ := Configured(Policy{Overlap: time.Hour}, t0, mustGen(t, RS256))
	_ = s.Add(RingUpstream, up)
	_ = s.Add(RingSession, sess)
	_ = s.Add(RingAgent, agent)
	_ = s.Add("ed", ed)
	_ = s.Add("rs", rs)
	return s
}

func TestFileRoundTrip(t *testing.T) {
	s := fullSet(t)
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Names(), ",") != strings.Join(s.Names(), ",") {
		t.Fatalf("names %v", got.Names())
	}
	for _, name := range s.Names() {
		a, b := s.Ring(name), got.Ring(name)
		if a.Alg() != b.Alg() || a.Policy() != b.Policy() {
			t.Errorf("%s: alg or policy", name)
		}
		sa, sb := a.Snapshot(), b.Snapshot()
		if sa.Current.ID() != sb.Current.ID() || !sa.Activated.Equal(sb.Activated) || !sa.Current.Created().Equal(sb.Current.Created()) {
			t.Errorf("%s: current", name)
		}
		if (sa.Next == nil) != (sb.Next == nil) || (sa.Next != nil && sa.Next.ID() != sb.Next.ID()) {
			t.Errorf("%s: next", name)
		}
		if len(sa.Previous) != len(sb.Previous) {
			t.Fatalf("%s: previous", name)
		}
		for i := range sa.Previous {
			if sa.Previous[i].Key.ID() != sb.Previous[i].Key.ID() || !sa.Previous[i].Until.Equal(sb.Previous[i].Until) {
				t.Errorf("%s: previous[%d]", name, i)
			}
		}
		// Loaded keys verify what the saved ones signed.
		if a.Alg() != A256GCM {
			kid, sig, err := a.Sign([]byte("m"))
			if err != nil || b.Verify(kid, []byte("m"), sig, t0) != nil {
				t.Errorf("%s: loaded ring does not verify: %v", name, err)
			}
		}
	}
	if !bytes.Equal(s.JWKS(t0), got.JWKS(t0)) {
		t.Error("JWKS differs after a round trip")
	}
	b1, _ := s.Marshal()
	b2, _ := got.Marshal()
	if !bytes.Equal(b1, b2) {
		t.Error("Marshal is not stable across a round trip")
	}
	// Saving again replaces the file and leaves no temporary files.
	if err := got.Save(path); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(filepath.Dir(path)); len(ents) != 1 {
		t.Errorf("%d files in the directory", len(ents))
	}
}

func TestSaveFailures(t *testing.T) {
	s := fullSet(t)
	if err := s.Save(filepath.Join(t.TempDir(), "missing", "keys.json")); err == nil {
		t.Error("Save into a missing directory")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "keys.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(filepath.Join(dir, "keys.json")); err == nil {
		t.Error("Save over a directory")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("a failed Save left %d entries", len(ents))
	}
	if _, err := Load(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("Load of a missing file")
	}
	if _, err := Load(dir); err == nil {
		t.Error("Load of a directory")
	}
}

// edit marshals a set, lets f change the decoded JSON and re-encodes it.
func edit(t *testing.T, f func(m map[string]any)) []byte {
	t.Helper()
	b, _ := fullSet(t).Marshal()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, _ := json.Marshal(m)
	return out
}

func TestUnmarshalRefuses(t *testing.T) {
	byName := func(m map[string]any, name string) map[string]any {
		for _, r := range m["rings"].([]any) {
			if r := r.(map[string]any); r["name"] == name {
				return r
			}
		}
		panic(name)
	}
	cur := func(m map[string]any, name string) map[string]any {
		return byName(m, name)["current"].(map[string]any)
	}
	other := mustGen(t, ES256)
	otherDER, _ := x509.MarshalPKCS8PrivateKey(other.Signer())
	edKey := mustGen(t, EdDSA)
	edDER, _ := x509.MarshalPKCS8PrivateKey(edKey.Signer())
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xDER, _ := x509.MarshalPKCS8PrivateKey(x)
	cases := map[string][]byte{
		"not json":      []byte("{"),
		"trailing":      append(edit(t, func(map[string]any) {}), []byte(" {}")...),
		"unknown field": edit(t, func(m map[string]any) { m["extra"] = 1 }),
		"version":       edit(t, func(m map[string]any) { m["version"] = 2 }),
		"too big":       bytes.Repeat([]byte(" "), MaxFileBytes+1),
		"dup name":      edit(t, func(m map[string]any) { byName(m, "ed")["name"] = "rs" }),
		"bad name":      edit(t, func(m map[string]any) { byName(m, "ed")["name"] = "Ed" }),
		"rotate_every":  edit(t, func(m map[string]any) { byName(m, RingUpstream)["rotate_every"] = "soon" }),
		"overlap":       edit(t, func(m map[string]any) { byName(m, RingUpstream)["overlap"] = "1x" }),
		"bad policy":    edit(t, func(m map[string]any) { byName(m, RingUpstream)["overlap"] = "0s" }),
		"ring alg":      edit(t, func(m map[string]any) { byName(m, "ed")["alg"] = "ES256" }),
		"key alg":       edit(t, func(m map[string]any) { cur(m, "ed")["alg"] = "PS256" }),
		"alg mismatch":  edit(t, func(m map[string]any) { cur(m, RingUpstream)["private"] = b64std(edDER) }),
		"kid mismatch":  edit(t, func(m map[string]any) { cur(m, RingUpstream)["private"] = b64std(otherDER) }),
		"bad private":   edit(t, func(m map[string]any) { cur(m, RingUpstream)["private"] = "!!" }),
		"bad pkcs8":     edit(t, func(m map[string]any) { cur(m, RingUpstream)["private"] = b64std([]byte("junk")) }),
		"x25519":        edit(t, func(m map[string]any) { cur(m, RingUpstream)["private"] = b64std(xDER) }),
		"secret on ec":  edit(t, func(m map[string]any) { cur(m, RingUpstream)["secret"] = "AAAA" }),
		"private on hs": edit(t, func(m map[string]any) { cur(m, RingAgent)["private"] = "AAAA" }),
		"bad secret":    edit(t, func(m map[string]any) { cur(m, RingAgent)["secret"] = "a+b/" }),
		"short secret":  edit(t, func(m map[string]any) { cur(m, RingAgent)["secret"] = "AAAA" }),
		"no kid":        edit(t, func(m map[string]any) { cur(m, RingAgent)["kid"] = "" }),
		"bad next":      edit(t, func(m map[string]any) { byName(m, RingUpstream)["next"].(map[string]any)["alg"] = "x" }),
		"bad previous": edit(t, func(m map[string]any) {
			byName(m, RingUpstream)["previous"].([]any)[0].(map[string]any)["key"].(map[string]any)["alg"] = "x"
		}),
		"dup key": edit(t, func(m map[string]any) {
			r := byName(m, RingUpstream)
			r["next"] = r["current"]
		}),
	}
	for name, b := range cases {
		if _, err := Unmarshal(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	path := filepath.Join(t.TempDir(), "keys.json")
	_ = os.WriteFile(path, cases["version"], 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("Load error %v must name the file", err)
	}
	_ = os.WriteFile(path, cases["too big"], 0o600)
	if _, err := Load(path); err == nil {
		t.Error("Load of an oversized file")
	}
}

func b64std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func writePEM(t *testing.T, blocks ...*pem.Block) string {
	t.Helper()
	var b bytes.Buffer
	for _, blk := range blocks {
		_ = pem.Encode(&b, blk)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadKeyFilePEM(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecPKCS8, _ := x509.MarshalPKCS8PrivateKey(ec)
	ecSEC1, _ := x509.MarshalECPrivateKey(ec)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	edPKCS8, _ := x509.MarshalPKCS8PrivateKey(ed)
	rsaPKCS1 := x509.MarshalPKCS1PrivateKey(rsaKey())
	rsaPKCS8, _ := x509.MarshalPKCS8PrivateKey(rsaKey())
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp"},
		NotBefore: t0, NotAfter: t0.Add(time.Hour)}
	cert, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ec.PublicKey, ec)

	ecKey, _ := FromSigner(ec, t0)
	rsaID := mustGen(t, RS256).ID()
	for name, tc := range map[string]struct {
		blocks []*pem.Block
		alg    Alg
		kid    string
	}{
		// WICKET_SIGNING_KEYS: PKCS #8 or SEC 1 P-256 keys.
		"ec pkcs8": {[]*pem.Block{{Type: "PRIVATE KEY", Bytes: ecPKCS8}}, ES256, ecKey.ID()},
		"ec sec1":  {[]*pem.Block{{Type: "EC PRIVATE KEY", Bytes: ecSEC1}}, ES256, ecKey.ID()},
		// SAML sp_key_file: PKCS #1 or PKCS #8 RSA, maybe after a cert.
		"rsa pkcs1": {[]*pem.Block{{Type: "RSA PRIVATE KEY", Bytes: rsaPKCS1}}, RS256, rsaID},
		"ed25519":   {[]*pem.Block{{Type: "PRIVATE KEY", Bytes: edPKCS8}}, EdDSA, ""},
	} {
		path := writePEM(t, tc.blocks...)
		k, err := ReadKeyFile(path, tc.alg)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if k.Alg() != tc.alg || (tc.kid != "" && k.ID() != tc.kid) {
			t.Errorf("%s: %s %s", name, k.Alg(), k.ID())
		}
		if fi, _ := os.Stat(path); !k.Created().Equal(fi.ModTime().UTC()) {
			t.Errorf("%s: created %v", name, k.Created())
		}
	}
	certThenKey := writePEM(t, &pem.Block{Type: "CERTIFICATE", Bytes: cert}, &pem.Block{Type: "PRIVATE KEY", Bytes: rsaPKCS8})
	if k, err := ReadKeyFile(certThenKey, ""); err != nil || k.Alg() != RS256 || k.ID() != rsaID {
		t.Errorf("cert then key: %v", err)
	}
	// A broken key block before a good one fails the file: the first
	// private key block counts.
	broken := writePEM(t, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("x")}, &pem.Block{Type: "PRIVATE KEY", Bytes: rsaPKCS8})
	if _, err := ReadKeyFile(broken, ""); !errors.Is(err, ErrKey) {
		t.Errorf("broken block first: %v", err)
	}
}

func TestReadKeyFileRefuses(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecPKCS8, _ := x509.MarshalPKCS8PrivateKey(ec)
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xPKCS8, _ := x509.MarshalPKCS8PrivateKey(x)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalECPrivateKey(p384)
	cases := map[string]struct {
		path string
		alg  Alg
	}{
		"wrong alg":  {writePEM(t, &pem.Block{Type: "PRIVATE KEY", Bytes: ecPKCS8}), RS256},
		"x25519":     {writePEM(t, &pem.Block{Type: "PRIVATE KEY", Bytes: xPKCS8}), ""},
		"p384":       {writePEM(t, &pem.Block{Type: "EC PRIVATE KEY", Bytes: p384DER}), ""},
		"junk":       {writePEM(t, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}), ""},
		"only cert":  {writePEM(t, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), ""},
		"bad want":   {writePEM(t, &pem.Block{Type: "PRIVATE KEY", Bytes: ecPKCS8}), "HS1"},
		"missing":    {filepath.Join(t.TempDir(), "nope"), ""},
		"hex for ec": {writeFile(t, strings.Repeat("ab", 32)), ES256},
		"hex no alg": {writeFile(t, strings.Repeat("ab", 32)), ""},
		"bad hex":    {writeFile(t, strings.Repeat("zz", 32)), HS256},
		"short hex":  {writeFile(t, "abcd"), A256GCM},
		"too big":    {writeFile(t, strings.Repeat("a", MaxFileBytes+1)), HS256},
	}
	for name, tc := range cases {
		if _, err := ReadKeyFile(tc.path, tc.alg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func writeFile(t *testing.T, s string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A GRANTD_TOKEN_KEY or `authz gateway genkey` value in a file, with the
// newline an editor adds.
func TestReadKeyFileHex(t *testing.T) {
	sec := bytes.Repeat([]byte{0xab}, 32)
	path := writeFile(t, hex.EncodeToString(sec)+"\n")
	for _, alg := range []Alg{HS256, A256GCM} {
		k, err := ReadKeyFile(path, alg)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := FromSecret(alg, "", sec, t0)
		if k.Alg() != alg || k.ID() != want.ID() || !bytes.Equal(k.Secret(), sec) {
			t.Errorf("%s: %s", alg, k.ID())
		}
	}
}

func TestParseSecretList(t *testing.T) {
	a, b := strings.Repeat("11", 32), strings.Repeat("22", 32)
	// WICKET_COOKIE_KEYS: the first key seals, the rest open.
	ks, err := ParseSecretList(A256GCM, " "+a+" , ,"+b+",", t0)
	if err != nil || len(ks) != 2 || ks[0].Alg() != A256GCM {
		t.Fatalf("cookie keys %v %v", ks, err)
	}
	r, err := Configured(Policy{}, t0, ks...)
	if err != nil || r.Current() != ks[0] || r.Lookup(ks[1].ID(), t0) != ks[1] {
		t.Fatalf("configured ring %v", err)
	}
	// TOOLGATE_SIGNING_KEYS: named keys, first one active.
	ks, err = ParseSecretList(HS256, "k2="+a+",k1="+b, t0)
	if err != nil || ks[0].ID() != "k2" || ks[1].ID() != "k1" {
		t.Fatalf("toolgate keys %v %v", ks, err)
	}
	for name, v := range map[string]string{
		"empty":     " , ",
		"short":     "abcd",
		"bad hex":   strings.Repeat("zz", 32),
		"bad kid":   "a b=" + a,
		"dup kid":   "k=" + a + ",k=" + b,
		"dup value": a + "," + a,
	} {
		if _, err := ParseSecretList(HS256, v, t0); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseSecretList(ES256, a, t0); !errors.Is(err, ErrAlg) {
		t.Errorf("ES256 list: %v", err)
	}
}
