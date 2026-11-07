package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const plain = "s3cr3t-value"

func logged(t *testing.T, opts Options, args ...any) (string, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	NewLogger(&buf, opts).Info("m", args...)
	return buf.String(), one(t, &buf)
}

func TestRedactKeys(t *testing.T) {
	for _, k := range []string{
		"password", "Password", "PASSWD", "secret", "token", "api_key", "API-Key", "apikey",
		"authorization", "Authorization", "proxy-authorization", "cookie", "Set-Cookie",
		"private_key", "client_secret", "access_token", "refresh_token", "id_token",
		"assertion", "SAMLResponse", "code_verifier",
		"upstream_token", "session_secret", "admin_password", "db_passwd", "vendor_api_key",
		"vendor_apikey", "signing_private_key", "X-Upstream-Token", "custom",
	} {
		t.Run(k, func(t *testing.T) {
			out, m := logged(t, Options{SecretKeys: []string{"Custom"}}, k, plain)
			if strings.Contains(out, plain) || m[k] != Redacted {
				t.Fatalf("%s not redacted: %s", k, out)
			}
		})
	}
	// Keys that only look like secrets keep their values.
	for _, k := range []string{"token_ttl", "upstream_token_ttl", "key_id", "kid", "tokens", "secretary", "password_set", "cache_key"} {
		out, m := logged(t, Options{}, k, plain)
		if m[k] != plain {
			t.Errorf("%s redacted: %s", k, out)
		}
	}
	// An empty value is not a secret: it says the value is unset.
	if _, m := logged(t, Options{}, "password", ""); m["password"] != "" {
		t.Errorf("empty password written as %v", m["password"])
	}
	// Non-string values under a secret key are redacted too.
	for _, v := range []any{12345, []byte(plain), map[string]string{"v": plain}, struct{ V string }{plain}} {
		out, m := logged(t, Options{}, "token", v)
		if strings.Contains(out, plain) || strings.Contains(out, "12345") || m["token"] != Redacted {
			t.Errorf("token %T not redacted: %s", v, out)
		}
	}
}

func TestRedactInGroupsAndWith(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, Options{Subcommand: "gateway"}).With("cookie", plain).WithGroup("req").With("authorization", "Bearer "+plain)
	log.Info("m", slog.Group("upstream", "client_secret", plain, "host", "h"), "password", plain)
	if strings.Contains(buf.String(), plain) {
		t.Fatalf("secret written: %s", buf.String())
	}
	m := one(t, &buf)
	req := m["req"].(map[string]any)
	if m["cookie"] != Redacted || req["authorization"] != Redacted || req["password"] != Redacted ||
		req["upstream"].(map[string]any)["client_secret"] != Redacted || req["upstream"].(map[string]any)["host"] != "h" {
		t.Fatalf("got %v", m)
	}
}

func TestSecretType(t *testing.T) {
	s := Secret(plain)
	out, m := logged(t, Options{}, "harmless", s, "nested", slog.GroupValue(slog.Any("v", s)))
	if strings.Contains(out, plain) || m["harmless"] != Redacted {
		t.Fatalf("Secret written: %s", out)
	}
	for _, f := range []string{"%v", "%s", "%+v", "%#v", "%q"} {
		if got := fmt.Sprintf(f, s); strings.Contains(got, plain) {
			t.Errorf("fmt %s printed the secret: %s", f, got)
		}
	}
	b, err := json.Marshal(struct {
		K Secret `json:"k"`
		P *Secret
	}{s, &s})
	if err != nil || strings.Contains(string(b), plain) {
		t.Errorf("json: %s %v", b, err)
	}
	if s.Reveal() != plain {
		t.Error("Reveal")
	}
	// Through an error message the caller is responsible, but the value
	// formatted into it is still redacted.
	if err := fmt.Errorf("login with %v failed", s); strings.Contains(err.Error(), plain) {
		t.Errorf("error: %v", err)
	}
}

type creds struct {
	User     string `json:"user"`
	Password string `json:"password_hash" log:"secret"`
	Key      []byte `log:"secret"`
	Note     string `json:"note,omitempty" log:"secret"`
	Hidden   string `json:"-" log:"secret"`
	Port     int    `json:"port,omitempty"`
	internal string // unexported fields are never written
}

type Base struct {
	Tenant string `json:"tenant"`
	Token  string `json:"tk" log:"secret"`
}

type request struct {
	Base
	*Extra
	ID      string            `json:"id"`
	Creds   creds             `json:"creds"`
	Ptr     *creds            `json:"ptr"`
	List    []creds           `json:"list"`
	ByName  map[string]*creds `json:"by_name"`
	Plain   map[string]string `json:"plain"`
	Name    string            `json:"name"`
	Ignored string            `json:"-"`
}

type Extra struct {
	Name  string `json:"name"` // request.Name is shallower and wins
	Grant string `json:"grant" log:"secret"`
}

func TestRedactTaggedFields(t *testing.T) {
	c := creds{User: "alice", Password: plain, Key: []byte(plain), Hidden: plain, internal: plain}
	out, m := logged(t, Options{}, "c", c, "p", &c)
	if strings.Contains(out, plain) {
		t.Fatalf("secret written: %s", out)
	}
	for _, k := range []string{"c", "p"} {
		g := m[k].(map[string]any)
		want := map[string]any{"user": "alice", "password_hash": Redacted, "Key": Redacted}
		if len(g) != len(want) {
			t.Errorf("%s: got %v, want %v (omitempty, - and unexported fields left out)", k, g, want)
		}
		for f, v := range want {
			if g[f] != v {
				t.Errorf("%s.%s = %v, want %v", k, f, g[f], v)
			}
		}
	}

	r := request{
		Base:   Base{Tenant: "acme", Token: plain},
		Extra:  &Extra{Name: "e", Grant: plain},
		ID:     "r1",
		Creds:  c,
		Ptr:    &c,
		List:   []creds{c},
		ByName: map[string]*creds{"a": &c},
		Plain:  map[string]string{"x": "y"},
		Name:   "n", Ignored: plain,
	}
	out, m = logged(t, Options{}, "r", r)
	if strings.Contains(out, plain) {
		t.Fatalf("secret written: %s", out)
	}
	g := m["r"].(map[string]any)
	for f, v := range map[string]any{
		"tenant": "acme", "tk": Redacted, "grant": Redacted, "id": "r1", "list": Redacted, "by_name": Redacted, "name": "n",
	} {
		if g[f] != v {
			t.Errorf("r.%s = %v, want %v", f, g[f], v)
		}
	}
	if g["creds"].(map[string]any)["password_hash"] != Redacted || g["ptr"].(map[string]any)["user"] != "alice" {
		t.Errorf("nested: %v", g)
	}
	if g["plain"].(map[string]any)["x"] != "y" {
		t.Errorf("a map without secrets is written as it is: %v", g["plain"])
	}

	// A nil embedded pointer is left out, as encoding/json does.
	r.Extra = nil
	out, _ = logged(t, Options{}, "r", r)
	if strings.Contains(out, `"grant"`) || strings.Contains(out, plain) {
		t.Errorf("nil embedded: %s", out)
	}
}

type untagged struct {
	A string `json:"a"`
	B int
}

type cyclic struct {
	Name string  `json:"name"`
	Next *cyclic `json:"next"`
	Pass string  `json:"pass" log:"x, secret"`
}

type cyclicPlain struct {
	Name string
	Next *cyclicPlain
}

type selfRendering struct {
	Pass string `log:"secret"`
}

func (s selfRendering) MarshalJSON() ([]byte, error) { return []byte(`{"pass":"own"}`), nil }

type secretErr struct {
	Pass string `log:"secret"`
}

func (secretErr) Error() string { return "failed" }

func TestRedactLeavesOtherValuesAlone(t *testing.T) {
	var nilCreds *creds
	var arr [1]creds
	arr[0].Password = plain
	out, m := logged(t, Options{},
		"u", untagged{"x", 2}, "nilp", nilCreds, "nil", nil, "e", errors.New("boom"),
		"self", selfRendering{plain}, "err", secretErr{plain}, "arr", arr,
		"cyc", &cyclic{Name: "a", Pass: plain, Next: &cyclic{Name: "b", Pass: plain}},
		"cp", &cyclicPlain{Name: "a", Next: &cyclicPlain{Name: "b"}},
	)
	if strings.Contains(out, plain) {
		t.Fatalf("secret written: %s", out)
	}
	if u := m["u"].(map[string]any); u["a"] != "x" || u["B"] != float64(2) {
		t.Errorf("untagged: %v", u)
	}
	if m["nilp"] != nil || m["nil"] != nil || m["e"] != "boom" || m["err"] != "failed" || m["arr"] != Redacted {
		t.Errorf("got %v", m)
	}
	if m["self"].(map[string]any)["pass"] != "own" {
		t.Errorf("a json.Marshaler renders itself: %v", m["self"])
	}
	cyc := m["cyc"].(map[string]any)
	if cyc["pass"] != Redacted || cyc["next"].(map[string]any)["pass"] != Redacted {
		t.Errorf("cyclic: %v", cyc)
	}
	if m["cp"].(map[string]any)["Next"].(map[string]any)["Name"] != "b" {
		t.Errorf("cyclic without secrets: %v", m["cp"])
	}
}

func TestTypeInfoCached(t *testing.T) {
	_, _ = logged(t, Options{}, "c", creds{})
	_, _ = logged(t, Options{}, "c", creds{})
	n := 0
	typeInfos.Range(func(any, any) bool { n++; return true })
	if n == 0 {
		t.Fatal("no type info cached")
	}
}
