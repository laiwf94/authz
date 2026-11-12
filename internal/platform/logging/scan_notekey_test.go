package logging

import (
	"strings"
	"testing"
)

// An audit checkpoint signing key in note form is a private key; its
// public half is not.
func TestScanNoteSigningKey(t *testing.T) {
	key := "PRIVATE+" + "KEY+audit.example+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz"
	for _, in := range []string{
		key,
		`{"msg":"start","AUTHZ_AUDIT_SIGNING_KEY":"` + key + `"}`,
		"level=warn key=" + key + " end",
	} {
		found := false
		for _, f := range Scan([]byte(in)) {
			found = found || f.Rule == RulePrivateKey
		}
		if !found {
			t.Errorf("Scan(%q) found no private key", in)
		}
	}
	for _, in := range []string{
		"audit.example+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
		"the PRIVATE+KEY+ prefix names a signing key",
		strings.Repeat("PRIVATE+KEY+x+0000000g+", 3),
	} {
		for _, f := range Scan([]byte(in)) {
			if f.Rule == RulePrivateKey {
				t.Errorf("Scan(%q) found a private key", in)
			}
		}
	}
}
