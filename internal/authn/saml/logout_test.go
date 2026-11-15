package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/laiwf94/authz/internal/authn/fakeidp"
	dsig "github.com/russellhaering/goxmldsig"
)

const sloURL = "https://gw.test/saml/partner/slo"

// sloEnv is an SP and a fake IdP that both do single logout.
type sloEnv struct {
	*env
}

func newSLOEnv(t testing.TB, bindings ...string) *sloEnv {
	t.Helper()
	clk := &clock{t: time.Now()}
	idp, err := fakeidp.New(fakeidp.Config{Issuer: "https://idp.test", Now: clk.now,
		ServiceProviders: []fakeidp.ServiceProvider{{EntityID: spEntity, ACSURL: acsURL, SignAssertion: true,
			SingleLogoutURL: sloURL, LogoutCert: spCert}}})
	if err != nil {
		t.Fatal(err)
	}
	idp.EnableSingleLogout(bindings...)
	md, err := ParseIdPMetadata(idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, idp: idp, clk: clk, md: md}
	e.sp = e.newSP(func(c *Config) { c.SLOURL = sloURL })
	return &sloEnv{e}
}

// toIdP delivers an SP message to the fake IdP as a browser would.
func (e *sloEnv) toIdP(m *Message) *httptest.ResponseRecorder {
	e.t.Helper()
	var req *http.Request
	if m.Binding == BindingRedirect {
		req = httptest.NewRequest(http.MethodGet, m.URL, nil)
	} else {
		req = httptest.NewRequest(http.MethodPost, m.URL, strings.NewReader(m.Form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	e.idp.ServeHTTP(rec, req)
	return rec
}

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// fromIdP reads the message the IdP sent back to the SP: a redirect or an
// auto-posting form.
func (e *sloEnv) fromIdP(rec *httptest.ResponseRecorder) (method, rawQuery string, form url.Values) {
	e.t.Helper()
	switch rec.Code {
	case http.StatusFound:
		u, err := url.Parse(rec.Header().Get("Location"))
		if err != nil || u.Scheme+"://"+u.Host+u.Path != sloURL {
			e.t.Fatalf("redirect to %q", rec.Header().Get("Location"))
		}
		return http.MethodGet, u.RawQuery, nil
	case http.StatusOK:
		form = url.Values{}
		for _, m := range hiddenInput.FindAllStringSubmatch(rec.Body.String(), -1) {
			form.Set(m[1], html.UnescapeString(m[2]))
		}
		return http.MethodPost, "", form
	}
	e.t.Fatalf("IdP answered %d: %s", rec.Code, rec.Body.String())
	return
}

func (e *sloEnv) idpRequest(o fakeidp.SAMLLogoutOptions) (method, rawQuery string, form url.Values, id string) {
	e.t.Helper()
	if o.SP == "" {
		o.SP = spEntity
	}
	if o.NameID == "" {
		o.NameID = "carol@partner.example"
	}
	target, form, id, err := e.idp.SAMLLogoutRequest(o)
	if err != nil {
		e.t.Fatal(err)
	}
	if form != nil {
		return http.MethodPost, "", form, id
	}
	u, _ := url.Parse(target)
	if u.Scheme+"://"+u.Host+u.Path != sloURL {
		e.t.Fatalf("request sent to %s", target)
	}
	return http.MethodGet, u.RawQuery, nil, id
}

func TestLogoutMetadata(t *testing.T) {
	e := newSLOEnv(t)
	if len(e.md.SingleLogout) != 2 || e.md.SingleLogout[BindingRedirect].Location != "https://idp.test/saml/slo" ||
		e.md.SingleLogout[BindingPOST].Location != "https://idp.test/saml/slo" {
		t.Fatalf("IdP endpoints %+v", e.md.SingleLogout)
	}
	good := string(e.idp.Metadata())
	slo := `<md:SingleLogoutService Binding="` + BindingRedirect + `" Location="https://idp.test/saml/slo"/>`
	if !strings.Contains(good, slo) {
		t.Fatalf("fixture changed:\n%s", good)
	}
	withResp := strings.Replace(good, slo, `<md:SingleLogoutService Binding="`+BindingRedirect+
		`" Location="HTTPS://idp.test/slo" ResponseLocation="https://idp.test/slo/done"/>`+
		`<md:SingleLogoutService Binding="`+BindingRedirect+`" Location="https://second.test/slo"/>`+
		`<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://soap.test/"/>`, 1)
	md, err := ParseIdPMetadata([]byte(withResp))
	if err != nil {
		t.Fatal(err)
	}
	if ep := md.SingleLogout[BindingRedirect]; ep.Location != "https://idp.test/slo" || ep.ResponseLocation != "https://idp.test/slo/done" {
		t.Fatalf("endpoint %+v: the first per binding, scheme as checked", ep)
	}
	for name, x := range map[string]string{
		"http Location":         strings.Replace(good, slo, `<md:SingleLogoutService Binding="`+BindingRedirect+`" Location="http://idp.test/slo"/>`, 1),
		"no Location":           strings.Replace(good, slo, `<md:SingleLogoutService Binding="`+BindingRedirect+`"/>`, 1),
		"http ResponseLocation": strings.Replace(good, slo, `<md:SingleLogoutService Binding="`+BindingRedirect+`" Location="https://idp.test/slo" ResponseLocation="http://x/"/>`, 1),
	} {
		if _, err := ParseIdPMetadata([]byte(x)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}

	out, _ := e.sp.Metadata()
	for _, b := range []string{BindingRedirect, BindingPOST} {
		if !strings.Contains(string(out), `<md:SingleLogoutService Binding="`+b+`" Location="`+sloURL+`"/>`) {
			t.Errorf("SP metadata lacks the %s SingleLogoutService:\n%s", b, out)
		}
	}
	if !e.sp.LogoutEnabled() {
		t.Fatal("logout not enabled")
	}
	// Without a key, an SLO URL or an IdP endpoint there is no single
	// logout, and the metadata says nothing about it.
	plain := newEnv(t)
	for name, sp := range map[string]*SP{
		"no key":          e.newSP(func(c *Config) { c.SLOURL, c.Key, c.Cert = sloURL, nil, nil }),
		"no SLO URL":      e.newSP(nil),
		"IdP without SLO": plain.newSP(func(c *Config) { c.SLOURL = sloURL }),
	} {
		md, _ := sp.Metadata()
		if sp.LogoutEnabled() || strings.Contains(string(md), "SingleLogoutService") {
			t.Errorf("%s: single logout advertised", name)
		}
		if _, err := sp.NewLogoutRequest(reqID, "carol", "", ""); reasonOf(err) != ReasonLogoutDisabled {
			t.Errorf("%s: request: %v", name, err)
		}
		if _, err := sp.NewLogoutResponse(reqID, StatusSuccess, "", BindingRedirect); reasonOf(err) != ReasonLogoutDisabled {
			t.Errorf("%s: response: %v", name, err)
		}
		if _, err := sp.ReadLogout(http.MethodGet, "", nil); reasonOf(err) != ReasonLogoutDisabled {
			t.Errorf("%s: read: %v", name, err)
		}
	}
}

func TestSPInitiatedLogout(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bindings []string
		want     string
	}{
		{"redirect", nil, BindingRedirect},
		{"POST only", []string{fakeidp.POST}, BindingPOST},
		{"redirect only", []string{fakeidp.Redirect}, BindingRedirect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSLOEnv(t, tc.bindings...)
			e.sp = e.newSP(func(c *Config) { c.SLOURL, c.NameIDFormat = sloURL, NameIDEmail })
			m, err := e.sp.NewLogoutRequest(reqID, "carol@partner.example", "_idx1", "relay-1")
			if err != nil {
				t.Fatal(err)
			}
			if m.Binding != tc.want {
				t.Fatalf("binding %s", m.Binding)
			}
			rec := e.toIdP(m)
			got := e.idp.LogoutRequests()
			if len(got) != 1 || got[0].NameID != "carol@partner.example" || len(got[0].SessionIndex) != 1 ||
				got[0].SessionIndex[0] != "_idx1" || got[0].SP != spEntity {
				t.Fatalf("IdP saw %+v (answer %d %s)", got, rec.Code, rec.Body.String())
			}
			method, q, form := e.fromIdP(rec)
			in, err := e.sp.ReadLogout(method, q, form)
			if err != nil {
				t.Fatal(err)
			}
			if in.Response == nil || in.Request != nil || in.Response.InResponseTo != reqID || !in.Response.Success() ||
				in.RelayState != "relay-1" || in.Binding != tc.want {
				t.Fatalf("read %+v %+v", in, in.Response)
			}
			// Each response is used once.
			if _, err := e.sp.ReadLogout(method, q, form); reasonOf(err) != ReasonLogoutReplay {
				t.Fatalf("replay: %v", err)
			}
		})
	}
	// The request carries the configured NameID format, and none for
	// "unspecified", and a SessionIndex only when there is one.
	e := newSLOEnv(t, fakeidp.POST)
	m, _ := e.sp.NewLogoutRequest(reqID, "carol", "", "")
	raw, _ := base64.StdEncoding.DecodeString(m.Form.Get("SAMLRequest"))
	if s := string(raw); strings.Contains(s, "Format=") || strings.Contains(s, "SessionIndex") || m.Form.Has("RelayState") ||
		!strings.Contains(s, `Destination="https://idp.test/saml/slo"`) || !strings.Contains(s, "<ds:Signature") {
		t.Fatalf("request %s", s)
	}
	for name, err := range map[string]error{
		"bad ID":           second(e.sp.NewLogoutRequest("1", "carol", "", "")),
		"no NameID":        second(e.sp.NewLogoutRequest(reqID, "", "", "")),
		"bad SessionIndex": second(e.sp.NewLogoutRequest(reqID, "carol", "a b", "")),
		"bad InResponseTo": second(e.sp.NewLogoutResponse("", StatusSuccess, "", BindingPOST)),
	} {
		if reasonOf(err) != ReasonMalformed {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.sp.NewLogoutRequest(reqID, "carol", "", strings.Repeat("r", 81)); err == nil {
		t.Error("long RelayState accepted")
	}
}

func second[T any](_ T, err error) error { return err }

func TestIdPInitiatedLogout(t *testing.T) {
	for _, b := range []string{fakeidp.Redirect, fakeidp.POST} {
		t.Run(b, func(t *testing.T) {
			e := newSLOEnv(t)
			method, q, form, id := e.idpRequest(fakeidp.SAMLLogoutOptions{SessionIndex: []string{"_a", "_b"},
				Binding: b, RelayState: "idp-relay"})
			in, err := e.sp.ReadLogout(method, q, form)
			if err != nil {
				t.Fatal(err)
			}
			req := in.Request
			if req == nil || req.ID != id || req.NameID != "carol@partner.example" || len(req.SessionIndexes) != 2 ||
				req.SessionIndexes[1] != "_b" || in.RelayState != "idp-relay" {
				t.Fatalf("read %+v %+v", in, req)
			}
			m, err := e.sp.NewLogoutResponse(req.ID, StatusSuccess, in.RelayState, in.Binding)
			if err != nil {
				t.Fatal(err)
			}
			if m.Binding != in.Binding {
				t.Fatalf("answered on %s", m.Binding)
			}
			if rec := e.toIdP(m); rec.Code != 200 {
				t.Fatalf("IdP: %d %s", rec.Code, rec.Body.String())
			}
			if st, ok := e.idp.SAMLLogoutResult(id); !ok || st != StatusSuccess {
				t.Fatalf("IdP result %q %v", st, ok)
			}
			if _, err := e.sp.ReadLogout(method, q, form); reasonOf(err) != ReasonLogoutReplay {
				t.Fatalf("replay: %v", err)
			}
		})
	}
	// ResponseLocation, when the IdP gives one, is where responses go.
	e := newSLOEnv(t, fakeidp.Redirect)
	ep := e.md.SingleLogout[BindingRedirect]
	ep.ResponseLocation = "https://idp.test/slo/return?x=1"
	e.md.SingleLogout = map[string]Endpoint{BindingRedirect: ep}
	sp := e.newSP(func(c *Config) { c.SLOURL = sloURL })
	m, err := sp.NewLogoutResponse(reqID, StatusSuccess, "", BindingPOST)
	if err != nil || m.Binding != BindingRedirect || !strings.HasPrefix(m.URL, "https://idp.test/slo/return?x=1&SAMLResponse=") {
		t.Fatalf("%+v %v", m, err)
	}
}

// signRedirect builds an HTTP-Redirect query for xml signed by key with
// alg (RSA PKCS#1 v1.5).
func signRedirect(param, xml, relay, alg string, key *rsa.PrivateKey, h crypto.Hash) string {
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	fw.Write([]byte(xml))
	fw.Close()
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relay != "" {
		q += "&RelayState=" + url.QueryEscape(relay)
	}
	q += "&SigAlg=" + url.QueryEscape(alg)
	d := h.New()
	d.Write([]byte(q))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, h, d.Sum(nil))
	return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

// signPOST signs xml with the IdP key for the HTTP-POST binding.
func (e *sloEnv) signPOST(param, xml string) url.Values {
	e.t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xml); err != nil {
		e.t.Fatal(err)
	}
	ctx, _ := dsig.NewSigningContext(e.idp.SigningKey(), [][]byte{e.idp.Certificate().Raw})
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	_ = ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	sig, err := ctx.ConstructSignature(doc.Root(), true)
	if err != nil {
		e.t.Fatal(err)
	}
	doc.Root().InsertChildAt(1, sig)
	b, _ := doc.WriteToBytes()
	return url.Values{param: {base64.StdEncoding.EncodeToString(b)}}
}

// logoutResponseXML is a LogoutResponse from the IdP; attrs replace or add
// attributes on the root.
func (e *sloEnv) logoutResponseXML(status string, attrs ...string) string {
	a := map[string]string{"ID": "_resp1", "Version": "2.0", "IssueInstant": e.clk.now().UTC().Format(timeFormat),
		"Destination": sloURL, "InResponseTo": reqID}
	for i := 0; i+1 < len(attrs); i += 2 {
		a[attrs[i]] = attrs[i+1]
	}
	var b strings.Builder
	b.WriteString(`<samlp:LogoutResponse xmlns:samlp="` + NSProtocol + `" xmlns:saml="` + NSAssertion + `"`)
	for _, k := range []string{"ID", "Version", "IssueInstant", "Destination", "InResponseTo"} {
		if a[k] != "" {
			b.WriteString(" " + k + `="` + a[k] + `"`)
		}
	}
	b.WriteString(`><saml:Issuer>https://idp.test/saml/metadata</saml:Issuer>` + status + `</samlp:LogoutResponse>`)
	return b.String()
}

func statusXML(codes ...string) string {
	s := ""
	for i := len(codes) - 1; i >= 0; i-- {
		s = `<samlp:StatusCode Value="` + codes[i] + `">` + s + `</samlp:StatusCode>`
	}
	return `<samlp:Status>` + s + `</samlp:Status>`
}

func TestLogoutResponseStatus(t *testing.T) {
	e := newSLOEnv(t)
	key := e.idp.SigningKey()
	for i, tc := range []struct {
		status  string
		success bool
		sub     string
	}{
		{statusXML(StatusSuccess), true, ""},
		{statusXML(StatusSuccess, StatusPartialLogout), false, StatusPartialLogout},
		{statusXML(StatusResponder), false, ""},
	} {
		x := e.logoutResponseXML(tc.status, "ID", "_s"+string(rune('a'+i)))
		in, err := e.sp.ReadLogout(http.MethodGet, signRedirect("SAMLResponse", x, "", dsig.RSASHA256SignatureMethod, key, crypto.SHA256), nil)
		if err != nil {
			t.Fatal(err)
		}
		if in.Response.Success() != tc.success || in.Response.SubStatus != tc.sub {
			t.Errorf("%d: %+v", i, in.Response)
		}
	}
	// RSA-SHA512 is accepted too, and over POST.
	x := e.logoutResponseXML(statusXML(StatusSuccess), "ID", "_s512")
	if _, err := e.sp.ReadLogout(http.MethodGet, signRedirect("SAMLResponse", x, "", dsig.RSASHA512SignatureMethod, key, crypto.SHA512), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.sp.ReadLogout(http.MethodPost, "", e.signPOST("SAMLResponse", e.logoutResponseXML(statusXML(StatusSuccess), "ID", "_post"))); err != nil {
		t.Fatal(err)
	}
}

func TestReadLogoutRejects(t *testing.T) {
	e := newSLOEnv(t)
	key := e.idp.SigningKey()
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ok := statusXML(StatusSuccess)
	resp := func(attrs ...string) string { return e.logoutResponseXML(ok, attrs...) }
	get := func(param, x string) func() (string, string, url.Values) {
		return func() (string, string, url.Values) {
			return http.MethodGet, signRedirect(param, x, "", dsig.RSASHA256SignatureMethod, key, crypto.SHA256), nil
		}
	}
	idpReq := func(o fakeidp.SAMLLogoutOptions) func() (string, string, url.Values) {
		return func() (string, string, url.Values) {
			m, q, f, _ := e.idpRequest(o)
			return m, q, f
		}
	}
	mutate := func(f func(*etree.Element)) fakeidp.SAMLLogoutOptions { return fakeidp.SAMLLogoutOptions{Mutate: f} }
	setAttr := func(k, v string) fakeidp.SAMLLogoutOptions {
		return mutate(func(r *etree.Element) { r.CreateAttr(k, v) })
	}
	removeChild := func(tag string) fakeidp.SAMLLogoutOptions {
		return mutate(func(r *etree.Element) { r.RemoveChild(r.SelectElement(tag)) })
	}
	now := e.clk.now().UTC()
	cases := []struct {
		name   string
		build  func() (string, string, url.Values)
		reason string
	}{
		{"redirect unsigned", idpReq(fakeidp.SAMLLogoutOptions{Unsigned: true}), ReasonUnsigned},
		{"POST unsigned", idpReq(fakeidp.SAMLLogoutOptions{Unsigned: true, Binding: fakeidp.POST}), ReasonUnsigned},
		{"redirect signed by another key", idpReq(fakeidp.SAMLLogoutOptions{SignWithOther: otherKey}), ReasonSignature},
		{"POST signed by another key", idpReq(fakeidp.SAMLLogoutOptions{SignWithOther: otherKey, Binding: fakeidp.POST}), ReasonSignature},
		{"redirect RelayState changed after signing", func() (string, string, url.Values) {
			m, q, f, _ := e.idpRequest(fakeidp.SAMLLogoutOptions{RelayState: "a"})
			return m, strings.Replace(q, "RelayState=a", "RelayState=b", 1), f
		}, ReasonSignature},
		{"redirect RelayState added after signing", func() (string, string, url.Values) {
			m, q, f, _ := e.idpRequest(fakeidp.SAMLLogoutOptions{})
			return m, q + "&RelayState=x", f
		}, ReasonSignature},
		{"redirect SAMLRequest twice", func() (string, string, url.Values) {
			m, q, f, _ := e.idpRequest(fakeidp.SAMLLogoutOptions{})
			return m, q + "&SAMLRequest=AAAA", f
		}, ReasonMalformed},
		{"POST NameID changed after signing", func() (string, string, url.Values) {
			_, _, f, _ := e.idpRequest(fakeidp.SAMLLogoutOptions{Binding: fakeidp.POST})
			raw, _ := base64.StdEncoding.DecodeString(f.Get("SAMLRequest"))
			f.Set("SAMLRequest", base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte("carol@"), []byte("alice@"), 1)))
			return http.MethodPost, "", f
		}, ReasonSignature},
		{"POST two messages", func() (string, string, url.Values) {
			_, _, f, _ := e.idpRequest(fakeidp.SAMLLogoutOptions{Binding: fakeidp.POST})
			f.Add("SAMLResponse", f.Get("SAMLRequest"))
			return http.MethodPost, "", f
		}, ReasonMalformed},
		{"POST not base64", func() (string, string, url.Values) {
			return http.MethodPost, "", url.Values{"SAMLRequest": {"%%%"}}
		}, ReasonMalformed},
		{"POST not XML", func() (string, string, url.Values) {
			return http.MethodPost, "", url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte("<a>"))}}
		}, ReasonMalformed},
		{"POST too large", func() (string, string, url.Values) {
			return http.MethodPost, "", url.Values{"SAMLRequest": {strings.Repeat("A", maxEncodedResponse+4)}}
		}, ReasonMalformed},
		{"POST signature wrapped in a second copy", func() (string, string, url.Values) {
			_, _, f, _ := e.idpRequest(fakeidp.SAMLLogoutOptions{Binding: fakeidp.POST})
			raw, _ := base64.StdEncoding.DecodeString(f.Get("SAMLRequest"))
			doc := etree.NewDocument()
			doc.ReadFromBytes(raw)
			doc.Root().AddChild(doc.Root().Copy()) // same ID twice
			b, _ := doc.WriteToBytes()
			f.Set("SAMLRequest", base64.StdEncoding.EncodeToString(b))
			return http.MethodPost, "", f
		}, ReasonWrapping},
		{"redirect SigAlg RSA-SHA1", func() (string, string, url.Values) {
			return http.MethodGet, signRedirect("SAMLResponse", resp(), "", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", key, crypto.SHA256), nil
		}, ReasonSignature},
		{"redirect ECDSA SigAlg with an RSA key", func() (string, string, url.Values) {
			return http.MethodGet, signRedirect("SAMLResponse", resp(), "", dsig.ECDSASHA256SignatureMethod, key, crypto.SHA256), nil
		}, ReasonSignature},
		{"redirect Signature missing", func() (string, string, url.Values) {
			q := signRedirect("SAMLResponse", resp(), "", dsig.RSASHA256SignatureMethod, key, crypto.SHA256)
			return http.MethodGet, q[:strings.Index(q, "&Signature=")], nil
		}, ReasonUnsigned},
		{"redirect both messages", func() (string, string, url.Values) {
			return http.MethodGet, "SAMLRequest=a&" + signRedirect("SAMLResponse", resp(), "", dsig.RSASHA256SignatureMethod, key, crypto.SHA256), nil
		}, ReasonMalformed},
		{"redirect no message", func() (string, string, url.Values) { return http.MethodGet, "RelayState=x", nil }, ReasonMalformed},
		{"redirect bad escape", func() (string, string, url.Values) {
			return http.MethodGet, "SAMLResponse=%zz&SigAlg=a&Signature=b", nil
		}, ReasonMalformed},
		{"redirect not deflated", func() (string, string, url.Values) {
			q := "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("plain text"))) +
				"&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
			sum := sha256.Sum256([]byte(q))
			sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
			return http.MethodGet, q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig)), nil
		}, ReasonMalformed},
		{"redirect query too long", func() (string, string, url.Values) {
			return http.MethodGet, strings.Repeat("x", 2*maxEncodedResponse+1), nil
		}, ReasonMalformed},
		{"redirect with an XML signature too", get("SAMLResponse", strings.Replace(resp(), "</saml:Issuer>",
			`</saml:Issuer><ds:Signature xmlns:ds="`+NSDSig+`"/>`, 1)), ReasonMalformed},
		{"redirect not XML", get("SAMLResponse", "<a"), ReasonMalformed},
		{"PUT", func() (string, string, url.Values) { return http.MethodPut, "", nil }, ReasonMalformed},
		{"response sent as SAMLRequest", get("SAMLRequest", resp()), ReasonMalformed},
		{"AuthnRequest", get("SAMLRequest", `<samlp:AuthnRequest xmlns:samlp="`+NSProtocol+`"/>`), ReasonMalformed},
		{"long RelayState", func() (string, string, url.Values) {
			return http.MethodGet, signRedirect("SAMLResponse", resp(), strings.Repeat("r", 81), dsig.RSASHA256SignatureMethod, key, crypto.SHA256), nil
		}, ReasonMalformed},
		{"RelayState with a newline", func() (string, string, url.Values) {
			return http.MethodGet, signRedirect("SAMLResponse", resp(), "a\nb", dsig.RSASHA256SignatureMethod, key, crypto.SHA256), nil
		}, ReasonMalformed},
		{"wrong version", get("SAMLResponse", resp("Version", "1.1")), ReasonMalformed},
		{"bad ID", get("SAMLResponse", resp("ID", "1x")), ReasonMalformed},
		{"no IssueInstant", get("SAMLResponse", strings.Replace(resp(), " IssueInstant=", " X=", 1)), ReasonMalformed},
		{"bad IssueInstant", get("SAMLResponse", resp("IssueInstant", "yesterday")), ReasonMalformed},
		{"issued 11 minutes ago", get("SAMLResponse", resp("IssueInstant", now.Add(-11*time.Minute-DefaultSkew).Format(timeFormat))), ReasonExpired},
		{"issued in the future", get("SAMLResponse", resp("IssueInstant", now.Add(DefaultSkew+time.Minute).Format(timeFormat))), ReasonNotYetValid},
		{"no Destination", get("SAMLResponse", strings.Replace(resp(), ` Destination="`+sloURL+`"`, "", 1)), ReasonDestination},
		{"wrong Destination", get("SAMLResponse", resp("Destination", acsURL)), ReasonDestination},
		{"no InResponseTo", get("SAMLResponse", strings.Replace(resp(), ` InResponseTo="`+reqID+`"`, "", 1)), ReasonInResponseTo},
		{"no Status", get("SAMLResponse", e.logoutResponseXML("")), ReasonMalformed},
		{"empty StatusCode", get("SAMLResponse", e.logoutResponseXML(`<samlp:Status><samlp:StatusCode/></samlp:Status>`)), ReasonMalformed},
		{"two second-level codes", get("SAMLResponse", e.logoutResponseXML(`<samlp:Status><samlp:StatusCode Value="a">`+
			`<samlp:StatusCode Value="b"/><samlp:StatusCode Value="c"/></samlp:StatusCode></samlp:Status>`)), ReasonMalformed},
		{"wrong Issuer", get("SAMLResponse", strings.Replace(resp(), "https://idp.test/saml/metadata", "https://evil.test", 1)), ReasonIssuer},
		{"no Issuer", get("SAMLResponse", strings.Replace(resp(), "<saml:Issuer>https://idp.test/saml/metadata</saml:Issuer>", "", 1)), ReasonIssuer},
		{"Issuer not an entity", get("SAMLResponse", strings.Replace(resp(), "<saml:Issuer>", `<saml:Issuer Format="`+NameIDEmail+`">`, 1)), ReasonIssuer},
		{"request NotOnOrAfter passed", idpReq(setAttr("NotOnOrAfter", now.Add(-DefaultSkew-time.Second).Format(timeFormat))), ReasonExpired},
		{"request bad NotOnOrAfter", idpReq(setAttr("NotOnOrAfter", "soon")), ReasonMalformed},
		{"request without NameID", idpReq(removeChild("NameID")), ReasonSubject},
		{"request with an EncryptedID", idpReq(mutate(func(r *etree.Element) {
			r.RemoveChild(r.SelectElement("NameID"))
			r.CreateElement("saml:EncryptedID")
		})), ReasonSubject},
		{"request with two NameIDs", idpReq(mutate(func(r *etree.Element) { r.AddChild(r.SelectElement("NameID").Copy()) })), ReasonSubject},
		{"request with a NameID element inside", idpReq(mutate(func(r *etree.Element) { r.SelectElement("NameID").CreateElement("x") })), ReasonSubject},
		{"request with 17 SessionIndexes", idpReq(fakeidp.SAMLLogoutOptions{SessionIndex: strings.Fields(strings.Repeat("_i ", 17))}), ReasonMalformed},
		{"request with a SessionIndex holding a space", idpReq(fakeidp.SAMLLogoutOptions{SessionIndex: []string{"a b"}}), ReasonMalformed},
		{"request to another SP", idpReq(setAttr("Destination", "https://other.test/slo")), ReasonDestination},
	}
	for _, tc := range cases {
		method, q, form := tc.build()
		if _, err := e.sp.ReadLogout(method, q, form); err == nil || reasonOf(err) != tc.reason {
			t.Errorf("%s: got %v, want %s", tc.name, err, tc.reason)
		}
	}
	// A full replay cache refuses rather than forgets.
	full := e.newSP(func(c *Config) { c.SLOURL, c.Replay = sloURL, NewReplayCache(1, e.clk.now) })
	m, q, f, _ := e.idpRequest(fakeidp.SAMLLogoutOptions{})
	if _, err := full.ReadLogout(m, q, f); err != nil {
		t.Fatal(err)
	}
	m, q, f, _ = e.idpRequest(fakeidp.SAMLLogoutOptions{})
	if _, err := full.ReadLogout(m, q, f); reasonOf(err) != ReasonLogoutReplay {
		t.Fatalf("full cache: %v", err)
	}
}

// An encoder that leaves '+' unescaped in base64 still interoperates.
func TestReadLogoutUnescapedPlus(t *testing.T) {
	e := newSLOEnv(t)
	for i := 0; i < 50; i++ {
		x := e.logoutResponseXML(statusXML(StatusSuccess), "ID", "_plus"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		q := signRedirect("SAMLResponse", x, "", dsig.RSASHA256SignatureMethod, e.idp.SigningKey(), crypto.SHA256)
		// Such a sender signs the query as it sends it, '+' and all.
		dec, _ := url.QueryUnescape(strings.TrimPrefix(strings.SplitN(q, "&SigAlg=", 2)[0], "SAMLResponse="))
		if !strings.Contains(dec, "+") {
			continue
		}
		raw := "SAMLResponse=" + strings.NewReplacer("/", "%2F", "=", "%3D").Replace(dec) +
			"&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
		sum := sha256.Sum256([]byte(raw))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, e.idp.SigningKey(), crypto.SHA256, sum[:])
		raw += "&Signature=" + base64.StdEncoding.EncodeToString(sig) // '+' unescaped here too
		if _, err := e.sp.ReadLogout(http.MethodGet, raw, nil); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("no message with a '+' in 50 tries")
}

func ecCert(t *testing.T, curve elliptic.Curve, notAfter time.Time) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(curve, rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ec"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return k, c
}

func TestVerifyQuerySignature(t *testing.T) {
	msg := []byte("SAMLRequest=abc&SigAlg=x")
	now := time.Now()
	k, c := ecCert(t, elliptic.P384(), now.Add(time.Hour))
	sum := crypto.SHA384.New()
	sum.Write(msg)
	r, s, _ := ecdsa.Sign(rand.Reader, k, sum.Sum(nil))
	raw := make([]byte, 96)
	r.FillBytes(raw[:48])
	s.FillBytes(raw[48:])
	der, _ := ecdsa.SignASN1(rand.Reader, k, sum.Sum(nil))
	rsaSig, _ := rsa.SignPKCS1v15(rand.Reader, spKey, crypto.SHA384, sum.Sum(nil))
	expired := *c
	expired.NotAfter = now.Add(-time.Minute)
	for _, tc := range []struct {
		name  string
		alg   string
		sig   []byte
		certs []*x509.Certificate
		ok    bool
	}{
		{"ECDSA r||s", dsig.ECDSASHA384SignatureMethod, raw, []*x509.Certificate{spCert, c}, true},
		{"ECDSA DER", dsig.ECDSASHA384SignatureMethod, der, []*x509.Certificate{c}, false},
		{"ECDSA, other message", dsig.ECDSASHA384SignatureMethod, append([]byte{1}, raw[1:]...), []*x509.Certificate{c}, false},
		{"RSA alg, EC key", dsig.RSASHA384SignatureMethod, raw, []*x509.Certificate{c}, false},
		{"RSA", dsig.RSASHA384SignatureMethod, rsaSig, []*x509.Certificate{c, spCert}, true},
		{"ECDSA alg, RSA key", dsig.ECDSASHA384SignatureMethod, rsaSig, []*x509.Certificate{spCert}, false},
		{"expired certificate", dsig.ECDSASHA384SignatureMethod, raw, []*x509.Certificate{&expired}, false},
		{"unknown alg", "rsa-md5", rsaSig, []*x509.Certificate{spCert}, false},
	} {
		if err := verifyQuerySignature(msg, tc.alg, tc.sig, tc.certs, now); (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestResponseSessionIndex(t *testing.T) {
	e := newEnv(t)
	res, err := e.sp.ParseResponse(encode(t, e.doc(respOpts{signAssertion: true})), reqID)
	if err != nil || !ValidSessionIndex(res.SessionIndex) {
		t.Fatalf("%+v %v", res, err)
	}
	for _, v := range []string{"a b", strings.Repeat("x", 256), "é"} {
		doc := e.doc(respOpts{signAssertion: true, beforeSign: func(a *etree.Element) {
			a.SelectElement("AuthnStatement").CreateAttr("SessionIndex", v)
		}})
		if _, err := e.sp.ParseResponse(encode(t, doc), reqID); reasonOf(err) != ReasonMalformed {
			t.Errorf("SessionIndex %q: %v", v, err)
		}
	}
	doc := e.doc(respOpts{signAssertion: true, beforeSign: func(a *etree.Element) {
		a.SelectElement("AuthnStatement").RemoveAttr("SessionIndex")
	}})
	if res, err := e.sp.ParseResponse(encode(t, doc), reqID); err != nil || res.SessionIndex != "" {
		t.Fatalf("no SessionIndex: %+v %v", res, err)
	}
}

func FuzzReadLogout(f *testing.F) {
	e := newSLOEnv(f)
	_, q, _, _ := e.idpRequest(fakeidp.SAMLLogoutOptions{SessionIndex: []string{"_a"}, RelayState: "r"})
	f.Add(true, q)
	_, _, form, _ := e.idpRequest(fakeidp.SAMLLogoutOptions{Binding: fakeidp.POST})
	f.Add(false, form.Encode())
	f.Add(true, "SAMLRequest=&SigAlg=&Signature=")
	sp := e.newSP(func(c *Config) { c.SLOURL = sloURL })
	f.Fuzz(func(t *testing.T, redirect bool, s string) {
		method, form := http.MethodGet, url.Values(nil)
		if !redirect {
			method = http.MethodPost
			form, _ = url.ParseQuery(s)
		}
		in, err := sp.ReadLogout(method, s, form)
		if err != nil {
			return
		}
		// Anything accepted is the fake IdP's own signed request, for
		// carol, and nothing else.
		if in.Request == nil || in.Request.NameID != "carol@partner.example" {
			t.Fatalf("fuzzed input accepted: %+v", in)
		}
	})
}
