package fakeidp_test

import (
	"crypto/rand"
	"crypto/rsa"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/fakeidp"
	"github.com/laiwf94/authz/internal/authn/saml"
)

// The IdP side of single logout, checked against the real service provider.

const (
	spEntity = "https://sp.test/saml/metadata"
	spACS    = "https://sp.test/saml/acs"
	spSLO    = "https://sp.test/saml/slo"
)

type sloFixture struct {
	t   *testing.T
	idp *fakeidp.IdP
	sp  *saml.SP
	key *rsa.PrivateKey
}

func newSLOFixture(t *testing.T, bindings ...string) *sloFixture {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, _ := fakeidp.SelfSignedCert(key, "sp", time.Now())
	idp, err := fakeidp.New(fakeidp.Config{Issuer: "https://idp.test",
		ServiceProviders: []fakeidp.ServiceProvider{{EntityID: spEntity, ACSURL: spACS, SignAssertion: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if !idp.SetSAMLLogout(spEntity, spSLO, cert) || idp.SetSAMLLogout("https://nobody.test", spSLO, cert) {
		t.Fatal("SetSAMLLogout")
	}
	idp.EnableSingleLogout(bindings...)
	md, err := saml.ParseIdPMetadata(idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	sp, err := saml.New(saml.Config{ProviderID: "p", EntityID: spEntity, ACSURL: spACS, SLOURL: spSLO, IdP: md, Key: key, Cert: cert})
	if err != nil {
		t.Fatal(err)
	}
	return &sloFixture{t: t, idp: idp, sp: sp, key: key}
}

func (f *sloFixture) serve(method, target string, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, body)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	f.idp.ServeHTTP(rec, req)
	return rec
}

func (f *sloFixture) send(m *saml.Message) *httptest.ResponseRecorder {
	if m.Binding == saml.BindingRedirect {
		return f.serve(http.MethodGet, m.URL, nil)
	}
	return f.serve(http.MethodPost, m.URL, m.Form)
}

var hidden = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// answer reads the IdP's LogoutResponse at the SP.
func (f *sloFixture) answer(rec *httptest.ResponseRecorder) *saml.Inbound {
	f.t.Helper()
	var in *saml.Inbound
	var err error
	switch rec.Code {
	case http.StatusFound:
		u, _ := url.Parse(rec.Header().Get("Location"))
		in, err = f.sp.ReadLogout(http.MethodGet, u.RawQuery, nil)
	case http.StatusOK:
		form := url.Values{}
		for _, m := range hidden.FindAllStringSubmatch(rec.Body.String(), -1) {
			form.Set(m[1], html.UnescapeString(m[2]))
		}
		in, err = f.sp.ReadLogout(http.MethodPost, "", form)
	default:
		f.t.Fatalf("IdP: %d %s", rec.Code, rec.Body.String())
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return in
}

func TestSingleLogoutFromSP(t *testing.T) {
	for _, b := range []string{fakeidp.Redirect, fakeidp.POST} {
		t.Run(b, func(t *testing.T) {
			f := newSLOFixture(t, b)
			md := string(f.idp.Metadata())
			if strings.Count(md, "SingleLogoutService") != 1 || strings.Index(md, "SingleLogoutService") > strings.Index(md, "NameIDFormat") {
				t.Fatalf("metadata:\n%s", md)
			}
			// Two logins: the SessionIndexes are recorded oldest first.
			var idx []string
			for n := 0; n < 2; n++ {
				u, _ := f.sp.AuthnRequestURL(saml.NewRequestID(), "")
				q, _ := url.Parse(u)
				rec := f.serve(http.MethodPost, "https://idp.test/saml/sso", url.Values{"query": {q.RawQuery},
					"username": {"carol"}, "password": {"carol-pass"}})
				if rec.Code != 200 {
					t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
				}
				got := f.idp.SAMLSessions("carol@partner.example")
				if len(got) != n+1 || (n == 1 && got[0] != idx[0]) {
					t.Fatalf("sessions %v after %v", got, idx)
				}
				idx = got
			}
			m, err := f.sp.NewLogoutRequest(saml.NewRequestID(), "carol@partner.example", idx[0], "rs")
			if err != nil {
				t.Fatal(err)
			}
			in := f.answer(f.send(m))
			if !in.Response.Success() || in.RelayState != "rs" {
				t.Fatalf("%+v", in.Response)
			}
			if got := f.idp.SAMLSessions("carol@partner.example"); len(got) != 1 || got[0] != idx[1] {
				t.Fatalf("left %v", got)
			}
			// No SessionIndex: every session of the user ends.
			m, _ = f.sp.NewLogoutRequest(saml.NewRequestID(), "carol@partner.example", "", "")
			f.answer(f.send(m))
			got := f.idp.LogoutRequests()
			if len(got) != 2 || got[1].EndedSessions != 1 || len(f.idp.SAMLSessions("carol@partner.example")) != 0 {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestSingleLogoutFromIdP(t *testing.T) {
	f := newSLOFixture(t)
	target, _, id, err := f.idp.SAMLLogoutRequest(fakeidp.SAMLLogoutOptions{SP: spEntity, NameID: "carol@partner.example"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(target)
	in, err := f.sp.ReadLogout(http.MethodGet, u.RawQuery, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := f.sp.NewLogoutResponse(in.Request.ID, saml.StatusSuccess, "", saml.BindingPOST)
	if rec := f.send(m); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if st, ok := f.idp.SAMLLogoutResult(id); !ok || st != saml.StatusSuccess {
		t.Fatalf("%q %v", st, ok)
	}
	// A second answer to the same request has nothing pending.
	m, _ = f.sp.NewLogoutResponse(in.Request.ID, saml.StatusSuccess, "", saml.BindingPOST)
	if rec := f.send(m); rec.Code != 400 {
		t.Fatalf("second answer: %d", rec.Code)
	}
	if _, _, _, err := f.idp.SAMLLogoutRequest(fakeidp.SAMLLogoutOptions{SP: "https://nobody.test"}); err == nil {
		t.Fatal("request for an unknown SP")
	}
	if _, _, err := f.idp.SAMLLogoutResponse("https://nobody.test", "_x", "", fakeidp.POST, ""); err == nil {
		t.Fatal("response for an unknown SP")
	}
	target, form, err := f.idp.SAMLLogoutResponse(spEntity, "_x", "", fakeidp.POST, "r")
	if err != nil || target != spSLO || form.Get("RelayState") != "r" {
		t.Fatalf("%s %v %v", target, form, err)
	}
	in, err = f.sp.ReadLogout(http.MethodPost, "", form)
	if err != nil || in.Response.InResponseTo != "_x" || !in.Response.Success() {
		t.Fatalf("%+v %v", in, err)
	}
}

func TestSingleLogoutEndpointRejects(t *testing.T) {
	f := newSLOFixture(t, fakeidp.Redirect)
	good, _ := f.sp.NewLogoutRequest(saml.NewRequestID(), "carol@partner.example", "", "")
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherCert, _ := fakeidp.SelfSignedCert(otherKey, "other", time.Now())
	md, _ := saml.ParseIdPMetadata(f.idp.Metadata())
	md.SingleLogout = map[string]saml.Endpoint{saml.BindingRedirect: {Location: "https://idp.test/saml/slo?x=1"},
		saml.BindingPOST: {Location: "https://idp.test/saml/slo"}}
	misdirected, _ := saml.New(saml.Config{EntityID: spEntity, ACSURL: spACS, SLOURL: spSLO, IdP: md, Key: f.key, Cert: otherCert})
	wrongDest, _ := misdirected.NewLogoutRequest(saml.NewRequestID(), "carol@partner.example", "", "")
	stranger, _ := saml.New(saml.Config{EntityID: "https://stranger.test", ACSURL: spACS, SLOURL: spSLO, IdP: md, Key: otherKey, Cert: otherCert})
	unknown, _ := stranger.NewLogoutRequest(saml.NewRequestID(), "carol@partner.example", "", "")
	forgedSP, _ := saml.New(saml.Config{EntityID: spEntity, ACSURL: spACS, SLOURL: spSLO, IdP: md, Key: otherKey, Cert: otherCert})
	forged, _ := forgedSP.NewLogoutRequest(saml.NewRequestID(), "carol@partner.example", "", "")
	md.SingleLogout = map[string]saml.Endpoint{saml.BindingPOST: {Location: "https://idp.test/saml/slo"}}
	forgedPOSTSP, _ := saml.New(saml.Config{EntityID: spEntity, ACSURL: spACS, SLOURL: spSLO, IdP: md, Key: otherKey, Cert: otherCert})
	forgedPOST, _ := forgedPOSTSP.NewLogoutRequest(saml.NewRequestID(), "carol@partner.example", "", "")
	unsigned := strings.Split(good.URL, "&SigAlg=")[0]
	for _, tc := range []struct {
		name   string
		method string
		target string
		form   url.Values
		code   int
	}{
		{"POST binding not enabled", http.MethodPost, "https://idp.test/saml/slo", url.Values{"SAMLRequest": {"x"}}, 404},
		{"bad query", http.MethodGet, "https://idp.test/saml/slo?%zz", nil, 400},
		{"not base64", http.MethodGet, "https://idp.test/saml/slo?SAMLRequest=%25", nil, 400},
		{"not deflated", http.MethodGet, "https://idp.test/saml/slo?SAMLRequest=AAAA", nil, 400},
		{"unsigned", http.MethodGet, unsigned, nil, 400},
		{"another SP's key", http.MethodGet, forged.URL, nil, 400},
		{"wrong Destination", http.MethodGet, wrongDest.URL, nil, 400},
		{"unknown SP", http.MethodGet, unknown.URL, nil, 400},
	} {
		if rec := f.serve(tc.method, tc.target, tc.form); rec.Code != tc.code {
			t.Errorf("%s: %d %s", tc.name, rec.Code, rec.Body.String())
		}
	}
	p := newSLOFixture(t, fakeidp.POST)
	for name, form := range map[string]url.Values{
		"not base64":       {"SAMLRequest": {"%%"}},
		"not XML":          {"SAMLResponse": {"PGE+"}},
		"another SP's key": forgedPOST.Form,
	} {
		if rec := p.serve(http.MethodPost, "https://idp.test/saml/slo", form); rec.Code != 400 {
			t.Errorf("POST %s: %d", name, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "https://idp.test/saml/slo", strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	p.idp.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Errorf("bad form: %d", rec.Code)
	}
	if rec := f.send(good); rec.Code != http.StatusFound {
		t.Fatalf("good: %d %s", rec.Code, rec.Body.String())
	}
}
