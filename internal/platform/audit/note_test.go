package audit

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
)

// The test vectors published with golang.org/x/mod/sumdb/note (its package
// documentation and note_test.go): two keys and a note signed by both.
const (
	peterSigner   = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz"
	peterVerifier = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"
	enochVerifier = "EnochRoot+af0cfe78+ATtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdop"
	vectorText    = "If you think cryptography is the answer to your problem,\n" +
		"then you don't know what your problem is.\n"
	peterSig = "— PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n"
	enochSig = "— EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5n2tiOHp+vAF1aGrQ5ovTG01oOTGwnWLox33WWd1RvMc+QQ=\n"
)

func mustVerifier(t *testing.T, s string) *Verifier {
	t.Helper()
	v, err := ParseVerifier(s)
	if err != nil {
		t.Fatalf("ParseVerifier(%q): %v", s, err)
	}
	return v
}

func TestNoteVectors(t *testing.T) {
	s, err := ParseSigner(peterSigner)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "PeterNeumann" {
		t.Fatalf("name %q", s.Name())
	}
	if got := s.Verifier().String(); got != peterVerifier {
		t.Fatalf("verifier of the signer\n got %s\nwant %s", got, peterVerifier)
	}
	// Ed25519 is deterministic, so the signature is the published one.
	msg, err := SignNote([]byte(vectorText), s)
	if err != nil {
		t.Fatal(err)
	}
	if want := vectorText + "\n" + peterSig; string(msg) != want {
		t.Fatalf("signed note\n got %q\nwant %q", msg, want)
	}
	peter, enoch := mustVerifier(t, peterVerifier), mustVerifier(t, enochVerifier)
	if peter.String() != peterVerifier || enoch.String() != enochVerifier {
		t.Fatal("verifier keys do not print as they were read")
	}
	both := []byte(vectorText + "\n" + peterSig + enochSig)
	for _, v := range []*Verifier{peter, enoch} {
		text, err := OpenNote(both, v)
		if err != nil {
			t.Fatalf("OpenNote by %s: %v", v.Name(), err)
		}
		if string(text) != vectorText {
			t.Fatalf("text %q", text)
		}
	}
	// One signature, by the other key.
	if _, err := OpenNote([]byte(vectorText+"\n"+enochSig), peter); err == nil || !strings.Contains(err.Error(), "not signed by PeterNeumann+c74f20a3") {
		t.Fatalf("note signed only by another key: %v", err)
	}
	// A changed signature by the key.
	bad := vectorText + "\n" + peterSig[:60] + "ABCD" + peterSig[60:]
	if _, err := OpenNote([]byte(bad), peter); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("changed signature: %v", err)
	}
	// Changed text.
	if _, err := OpenNote([]byte(strings.Replace(string(both), "problem", "Problem", 1)), peter); err == nil {
		t.Fatal("changed text verified")
	}
	// Too many signatures.
	if _, err := OpenNote([]byte(vectorText+"\n"+strings.Repeat(peterSig, 101)), peter); err != errMalformedNote {
		t.Fatalf("101 signatures: %v", err)
	}
	if _, err := OpenNote([]byte(vectorText+"\n"+strings.Repeat(peterSig, 100)), peter); err != nil {
		t.Fatalf("100 signatures: %v", err)
	}
}

func TestNoteMalformed(t *testing.T) {
	peter := mustVerifier(t, peterVerifier)
	for name, msg := range map[string]string{
		"empty":                "",
		"no signatures":        vectorText,
		"no blank line":        vectorText + peterSig,
		"empty signature part": vectorText + "\n",
		"no final newline":     vectorText + "\n" + strings.TrimSuffix(peterSig, "\n"),
		"not a signature line": vectorText + "\n" + "- PeterNeumann x08go\n",
		"bad base64":           vectorText + "\n" + "— PeterNeumann x08go!\n",
		"short signature":      vectorText + "\n" + "— PeterNeumann AAAA\n",
		"no name":              vectorText + "\n" + "—  x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n",
		"control character":    "a\tb\n\n" + peterSig,
		"invalid UTF-8":        "a\xffb\n\n" + peterSig,
	} {
		if _, err := OpenNote([]byte(msg), peter); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	s, _ := ParseSigner(peterSigner)
	for _, text := range []string{"", "no newline", "blank line at the end\n\n", "tab\there\n", "\xff\n"} {
		if _, err := SignNote([]byte(text), s); err == nil {
			t.Errorf("SignNote(%q) signed", text)
		}
	}
}

// Every cut and every changed byte of a key is refused, as x/mod's own
// tests require of its parser.
func TestKeyManglings(t *testing.T) {
	try := func(kind string, parse func(string) error, key string) {
		b := []byte(key)
		for i := 0; i <= len(b); i++ {
			for j := i + 1; j <= len(b); j++ {
				if (i != 0 || j != len(b)) && parse(string(b[i:j])) == nil {
					t.Errorf("%s %q accepted", kind, b[i:j])
				}
			}
		}
		for i := range b {
			b[i]++
			if parse(string(b)) == nil {
				t.Errorf("%s %q accepted", kind, b)
			}
			b[i]--
		}
	}
	try("verifier", func(s string) error { _, err := ParseVerifier(s); return err }, peterVerifier)
	try("signer", func(s string) error { _, err := ParseSigner(s); return err }, peterSigner)
	// Wrong length and unknown algorithm, with the key hash adjusted.
	for _, k := range []string{
		"PeterNeumann+cc469956+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TWBADKEY==",
		"PeterNeumann+173116ae+ZRpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
	} {
		if _, err := ParseVerifier(k); err == nil {
			t.Errorf("verifier %q accepted", k)
		}
	}
	if _, err := ParseVerifier(peterSigner); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Errorf("a signing key as verifier: %v", err)
	}
	if _, err := ParseSigner(peterVerifier); err == nil {
		t.Error("a verifier key as signer accepted")
	}
}

func TestSignerHidesKey(t *testing.T) {
	s, err := ParseSigner(peterSigner)
	if err != nil {
		t.Fatal(err)
	}
	secret := peterSigner[strings.LastIndexByte(peterSigner, '+')+1:]
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s", s, s, s, s)} {
		if strings.Contains(out, secret) || strings.Contains(out, "PRIVATE") {
			t.Fatalf("signer prints its key: %s", out)
		}
	}
	// Parse errors do not repeat the key either.
	for _, k := range []string{peterSigner + "x", strings.Replace(peterSigner, "c74f20a3", "c74f20a4", 1), peterSigner[:40]} {
		_, err := ParseSigner(k)
		if err == nil {
			t.Fatalf("%q accepted", k)
		}
		if strings.Contains(err.Error(), secret[:12]) {
			t.Fatalf("error repeats the key: %v", err)
		}
	}
}

func TestGenerateKey(t *testing.T) {
	skey, vkey, err := GenerateKey(rand.Reader, "audit.example")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v := mustVerifier(t, vkey)
	if s.Verifier().String() != vkey || v.Name() != "audit.example" {
		t.Fatalf("keys do not match: %s", vkey)
	}
	msg, err := SignNote([]byte("hello\n"), s)
	if err != nil {
		t.Fatal(err)
	}
	if text, err := OpenNote(msg, v); err != nil || !bytes.Equal(text, []byte("hello\n")) {
		t.Fatalf("OpenNote: %q, %v", text, err)
	}
	for _, name := range []string{"", "a b", "a+b", "a\nb", "\xff"} {
		if _, _, err := GenerateKey(rand.Reader, name); err == nil {
			t.Errorf("GenerateKey(%q) succeeded", name)
		}
	}
}
