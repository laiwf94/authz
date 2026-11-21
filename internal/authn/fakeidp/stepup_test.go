package fakeidp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
)

type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stepClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *stepClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newStepFixture(t *testing.T, cfg Config) (*fixture, *stepClock) {
	t.Helper()
	clk := &stepClock{t: time.Unix(1_800_000_000, 0)}
	srv := httptest.NewUnstartedServer(nil)
	cfg.Issuer = "http://" + srv.Listener.Addr().String()
	cfg.Now = clk.now
	cfg.Clients = []Client{{ID: "app", Secret: "pw", RedirectURIs: []string{"https://app/cb"}}}
	cfg.ServiceProviders = []ServiceProvider{{EntityID: "https://sp", ACSURL: "https://sp/acs", SignAssertion: true}}
	idp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = idp
	srv.Start()
	t.Cleanup(srv.Close)
	f := newFixture(t)
	f.idp, f.srv = idp, srv
	return f, clk
}

// login signs in at /authorize with extra request parameters and returns
// the ID token's claims, or the status and body of a refused form.
func (f *fixture) idTokenClaims(t *testing.T, extra url.Values, user, pass, otp string) (map[string]any, int, string) {
	t.Helper()
	q := goodAuthorize()
	for k, v := range extra {
		q[k] = v
	}
	resp, body := f.get(t, "/authorize?"+q.Encode())
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, body
	}
	q.Set("username", user)
	q.Set("password", pass)
	if otp != "" {
		q.Set("otp", otp)
	}
	resp, body = f.post(t, "/authorize", q, "", "")
	if resp.StatusCode != 302 {
		return nil, resp.StatusCode, body
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	resp, body = f.post(t, "/token", url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"https://app/cb"}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}, "app", "pw")
	if resp.StatusCode != 200 {
		t.Fatalf("token: %d %s", resp.StatusCode, body)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	json.Unmarshal([]byte(body), &tr)
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(tr.IDToken, ".")[1])
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	return claims, 200, ""
}

func TestOIDCStepUp(t *testing.T) {
	f, clk := newStepFixture(t, Config{})
	if _, body := f.get(t, "/.well-known/openid-configuration"); !strings.Contains(body, ACRMFA) {
		t.Fatal("discovery does not list the acr values")
	}
	// An ordinary login: a password, and a fresh authentication.
	c, _, _ := f.idTokenClaims(t, nil, "alice", "alice-pass", "")
	if c["acr"] != ACRPassword || int64(c["auth_time"].(float64)) != clk.now().Unix() {
		t.Fatalf("claims %v", c)
	}
	// The form asks for the code only when the login asks for MFA.
	q := goodAuthorize()
	if _, body := f.get(t, "/authorize?"+q.Encode()); strings.Contains(body, `name="otp"`) {
		t.Fatal("an ordinary login asks for the code")
	}
	mfa := url.Values{"acr_values": {"urn:other " + ACRMFA}, "max_age": {"300"}}
	q.Set("acr_values", ACRMFA)
	if _, body := f.get(t, "/authorize?"+q.Encode()); !strings.Contains(body, `name="otp"`) || !strings.Contains(body, `name="acr_values"`) {
		t.Fatal("an MFA login does not ask for the code")
	}
	for _, c := range []struct{ user, pass, otp string }{
		{"alice", "alice-pass", ""}, {"alice", "alice-pass", "000000"}, {"bob", "bob-pass", ""}, {"bob", "bob-pass", "246810"},
	} {
		if _, status, body := f.idTokenClaims(t, mfa, c.user, c.pass, c.otp); status != 401 || !strings.Contains(body, "one-time code") ||
			!strings.Contains(body, `name="max_age" value="300"`) {
			t.Errorf("%s with code %q: %d", c.user, c.otp, status)
		}
	}
	clk.add(time.Hour)
	c, _, _ = f.idTokenClaims(t, mfa, "alice", "alice-pass", "246810")
	if c["acr"] != ACRMFA || int64(c["auth_time"].(float64)) != clk.now().Unix() {
		t.Fatalf("MFA claims %v", c)
	}
	if _, status, _ := f.idTokenClaims(t, url.Values{"max_age": {"soon"}}, "alice", "alice-pass", ""); status != 400 {
		t.Fatalf("bad max_age: %d", status)
	}

	// A provider that ignores the request reports the first sign-in and
	// a password, whatever was asked.
	f.idp.SetIgnore(true, true)
	clk.add(time.Hour)
	c, _, _ = f.idTokenClaims(t, mfa, "alice", "alice-pass", "")
	if c["acr"] != ACRPassword || int64(c["auth_time"].(float64)) != clk.now().Add(-2*time.Hour).Unix() {
		t.Fatalf("ignoring claims %v", c)
	}
}

func TestSAMLStepUp(t *testing.T) {
	f, clk := newStepFixture(t, Config{})
	request := func(classRefs ...string) string {
		doc := etree.NewDocument()
		req := doc.CreateElement("samlp:AuthnRequest")
		req.CreateAttr("xmlns:samlp", nsProtocol)
		req.CreateAttr("xmlns:saml", nsAssertion)
		req.CreateAttr("ID", "_r1")
		req.CreateAttr("Destination", f.idp.Issuer()+"/saml/sso")
		req.CreateAttr("AssertionConsumerServiceURL", "https://sp/acs")
		req.CreateAttr("ForceAuthn", "true")
		req.CreateElement("saml:Issuer").SetText("https://sp")
		if len(classRefs) > 0 {
			rac := req.CreateElement("samlp:RequestedAuthnContext")
			for _, c := range classRefs {
				rac.CreateElement("saml:AuthnContextClassRef").SetText(c)
			}
		}
		b, _ := doc.WriteToBytes()
		return url.Values{"SAMLRequest": {deflate(b)}, "RelayState": {"rs"}}.Encode()
	}
	submit := func(query, user, pass, otp string) (int, *etree.Element) {
		t.Helper()
		form := url.Values{"query": {query}, "username": {user}, "password": {pass}}
		if otp != "" {
			form.Set("otp", otp)
		}
		resp, body := f.post(t, "/saml/sso", form, "", "")
		if resp.StatusCode != 200 {
			return resp.StatusCode, nil
		}
		m := strings.Split(strings.Split(body, `name="SAMLResponse" value="`)[1], `"`)[0]
		raw, _ := base64.StdEncoding.DecodeString(html.UnescapeString(m))
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(raw); err != nil {
			t.Fatal(err)
		}
		return 200, doc.Root().FindElement(".//AuthnStatement")
	}
	if _, body := f.get(t, "/saml/sso?"+request()); strings.Contains(body, `name="otp"`) {
		t.Fatal("an ordinary SAML login asks for the code")
	}
	if _, body := f.get(t, "/saml/sso?"+request(ACRMFA)); !strings.Contains(body, `name="otp"`) {
		t.Fatal("an MFA SAML login does not ask for the code")
	}
	if status, _ := submit(request(ACRMFA), "alice", "alice-pass", "1"); status != 401 {
		t.Fatalf("wrong code: %d", status)
	}
	status, as := submit(request(ACRMFA), "alice", "alice-pass", "246810")
	if status != 200 || as.FindElement(".//AuthnContextClassRef").Text() != ACRMFA ||
		as.SelectAttrValue("AuthnInstant", "") != clk.now().UTC().Format(timeFormat) {
		t.Fatalf("MFA statement: %d", status)
	}
	f.idp.SetIgnore(true, true)
	clk.add(time.Hour)
	_, as = submit(request(ACRMFA), "alice", "alice-pass", "")
	if as.FindElement(".//AuthnContextClassRef").Text() == ACRMFA ||
		as.SelectAttrValue("AuthnInstant", "") != clk.now().Add(-time.Hour).UTC().Format(timeFormat) {
		t.Fatal("an ignoring IdP still honoured the request")
	}
}

func deflate(b []byte) string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write(b)
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}
