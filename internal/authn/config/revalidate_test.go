package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// docWith is goodDoc with extra members on its oidc provider.
func docWith(oidcExtra string) string {
	return strings.Replace(goodDoc, `"client_secret_env": "SECRET"}`, `"client_secret_env": "SECRET"`+oidcExtra+`}`, 1)
}

func TestRevalidateConfig(t *testing.T) {
	r := Check([]byte(docWith(`, "revalidate": {"interval": "5m", "on_failure": "grace", "grace": "15m"}`)), getenvSecret)
	if len(r.Problems) != 0 {
		t.Fatalf("problems:\n%s", dump(r.Problems))
	}
	rv := r.Config.Providers[0].Revalidate
	if !rv.Enabled() || time.Duration(rv.Interval) != 5*time.Minute || rv.OnFailure != RevalidateGrace || time.Duration(rv.Grace) != 15*time.Minute {
		t.Fatalf("revalidate %+v", rv)
	}

	// on_failure defaults to end.
	r = Check([]byte(docWith(`, "revalidate": {"interval": "1m"}`)), getenvSecret)
	if len(r.Problems) != 0 || r.Config.Providers[0].Revalidate.OnFailure != RevalidateEnd {
		t.Fatalf("default: %+v\n%s", r.Config.Providers[0].Revalidate, dump(r.Problems))
	}
	// Absent: off.
	r = Check([]byte(goodDoc), getenvSecret)
	if r.Config.Providers[0].Revalidate.Enabled() {
		t.Fatal("revalidation on by default")
	}

	const p = "$.providers[0].revalidate"
	cases := map[string]struct {
		extra string
		want  []want
	}{
		"too often":     {`, "revalidate": {"interval": "10s"}`, []want{{p + ".interval", SeverityError, "between 30s and 24h"}}},
		"too rare":      {`, "revalidate": {"interval": "25h"}`, []want{{p + ".interval", SeverityError, "between 30s and 24h"}}},
		"no interval":   {`, "revalidate": {"on_failure": "grace", "grace": "1m"}`, []want{{p + ".interval", SeverityError, "set an interval"}}},
		"bad policy":    {`, "revalidate": {"interval": "1m", "on_failure": "ignore"}`, []want{{p + ".on_failure", SeverityError, `"ignore" is not`}}},
		"grace missing": {`, "revalidate": {"interval": "1m", "on_failure": "grace"}`, []want{{p + ".grace", SeverityError, "needs a grace"}}},
		"grace too long": {`, "revalidate": {"interval": "1m", "on_failure": "grace", "grace": "48h"}`,
			[]want{{p + ".grace", SeverityError, "needs a grace"}}},
		"grace with end": {`, "revalidate": {"interval": "1m", "on_failure": "end", "grace": "1m"}`,
			[]want{{p + ".grace", SeverityError, `grace needs on_failure "grace"`}}},
		"grace defaults to end": {`, "revalidate": {"interval": "1m", "grace": "1m"}`,
			[]want{{p + ".grace", SeverityError, `grace needs on_failure "grace"`}}},
		"unknown key": {`, "revalidate": {"interval": "1m", "intervall": "2m"}`,
			[]want{{p + ".intervall", SeverityError, "interval"}}},
		"bad duration":  {`, "revalidate": {"interval": "soon"}`, []want{{p + ".interval", SeverityError, "invalid duration"}}},
		"never reached": {`, "revalidate": {"interval": "24h"}`, []want{{p + ".interval", SeverityWarning, "before they are first revalidated"}}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			expect(t, checkDoc(t, docWith(c.extra)), c.want...)
		})
	}
}

func TestRevalidateOnSAML(t *testing.T) {
	doc := strings.Replace(goodDoc, `{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "SECRET"}`,
		`{"id": "corp", "type": "saml", "idp_metadata_url": "https://idp.example.com/md", "revalidate": {"interval": "5m"}}`, 1)
	got := checkDoc(t, doc)
	found := false
	for _, p := range got {
		if p.Path == "$.providers[0].revalidate" && p.Severity == SeverityError && strings.Contains(p.Message, "saml provider") {
			found = true
		}
	}
	if !found {
		t.Fatalf("revalidate on saml accepted:\n%s", dump(got))
	}
}

func TestRevalidateRoundTrips(t *testing.T) {
	r := Check([]byte(docWith(`, "revalidate": {"interval": "5m", "on_failure": "grace", "grace": "15m"}`)), getenvSecret)
	b, err := json.Marshal(r.Config.Providers[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"revalidate":{"interval":"5m0s","on_failure":"grace","grace":"15m0s"}`) {
		t.Fatalf("encoded %s", b)
	}
	// A provider without revalidation encodes a block that reads back as off.
	b, _ = json.Marshal(Provider{})
	if !strings.Contains(string(b), `"revalidate":{"interval":"0s","on_failure":"","grace":"0s"}`) {
		t.Fatalf("encoded %s", b)
	}
	expect(t, checkDoc(t, docWith(`, "revalidate": {"interval": "0s", "on_failure": "", "grace": "0s"}`)))
}
