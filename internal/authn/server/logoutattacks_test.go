package server

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/laiwf94/authz/internal/authn/fakeidp"
)

// The logout attack suites (#79): each case is a request an attacker could
// send to the gateway's logout endpoints, built the way they would build
// it, and names the refusal it must get. Every case is checked end to end
// through the gateway: the status, the audited reason, and that the
// session the request names is still signed in afterwards.
//
// The attacker is given more than a real one has wherever that makes the
// case sharper. Back-channel tokens are signed with the provider's own key,
// so only the claim under test is wrong; SAML messages are the provider's
// genuine, signed messages, altered after signing or with the signature
// taken off.

// auditCount counts the audit records of an event with this reason.
func (h *harness) auditCount(event, reason string) int {
	n := 0
	ev, rs := `"event":"`+event+`"`, `"reason":"`+reason+`"`
	for _, line := range strings.Split(h.logs.String(), "\n") {
		if strings.Contains(line, ev) && strings.Contains(line, rs) {
			n++
		}
	}
	return n
}

// logoutClaims are the claims of a valid logout token for the corp client
// naming sub and sid, with a fresh jti.
func (h *harness) logoutClaims(sub, sid string) map[string]any {
	now := h.clk.Now()
	c := map[string]any{"iss": h.idp.Issuer(), "aud": "wicket", "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": randomHex(h.t), "events": map[string]any{backchannelEvent: map[string]any{}}}
	if sub != "" {
		c["sub"] = sub
	}
	if sid != "" {
		c["sid"] = sid
	}
	return c
}

const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

func randomHex(t testing.TB) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

// signLogout signs claims with the provider's own key, typed logout+jwt.
func (h *harness) signLogout(typ string, claims map[string]any) string {
	h.t.Helper()
	tok, err := h.idp.SignJWTType(typ, claims)
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

// wantLogoutRefused posts a logout token and checks it is refused for
// reason, audited once more, and that br is still signed in.
func (h *harness) wantLogoutRefused(br *browser, body, reason string) {
	h.t.Helper()
	before := h.auditCount("logout_rejected", reason)
	code, out, _ := h.postLogout("/backchannel-logout/corp", formType, body)
	if code != http.StatusBadRequest || out["error"] != "invalid_request" || out["error_description"] != reason {
		h.t.Fatalf("got %d %v, want 400 %s", code, out, reason)
	}
	if got := h.auditCount("logout_rejected", reason); got != before+1 {
		h.t.Fatalf("audited %d refusals for %s, want %d", got, reason, before+1)
	}
	if c := br.auth("/", nil).StatusCode; c != http.StatusOK {
		h.t.Fatalf("a refused logout token signed the user out: %d", c)
	}
}

// TestBackchannelLogoutReplayAttacks replays logout tokens: a token is used
// once per provider, keyed by its jti, whatever bytes carry it, for as long
// as it would otherwise be accepted, across reloads and under concurrency.
func TestBackchannelLogoutReplayAttacks(t *testing.T) {
	h := backchannelHarness(t, harnessOpts{})

	// A captured token naming only the user must not end the sessions
	// they start after it was used.
	first := h.browser()
	first.loginOIDC("alice", "alice-pass", "")
	captured := h.signLogout("logout+jwt", h.logoutClaims("alice", ""))
	if code, out, _ := h.postLogout("/backchannel-logout/corp", formType, form(captured)); code != 200 {
		t.Fatalf("first use: %d %v", code, out)
	}
	if first.auth("/", nil).StatusCode == 200 {
		t.Fatal("the first use ended nothing")
	}
	later := h.browser()
	later.loginOIDC("alice", "alice-pass", "")

	t.Run("the same token again", func(t *testing.T) {
		h.t = t
		h.wantLogoutRefused(later, form(captured), reasonLogoutReplayed)
	})
	t.Run("percent-encoded differently", func(t *testing.T) {
		h.t = t
		var b strings.Builder
		b.WriteString("logout_token=")
		for i := 0; i < len(captured); i++ {
			fmt.Fprintf(&b, "%%%02X", captured[i])
		}
		h.wantLogoutRefused(later, b.String(), reasonLogoutReplayed)
	})
	t.Run("the same jti in a new token naming the new session", func(t *testing.T) {
		h.t = t
		sids := h.idp.Sessions("alice")
		c := h.logoutClaims("alice", sids[len(sids)-1])
		c["jti"] = jtiOf(t, captured)
		h.wantLogoutRefused(later, form(h.signLogout("logout+jwt", c)), reasonLogoutReplayed)
	})
	t.Run("after a reload", func(t *testing.T) {
		h.t = t
		if err := h.srv.Reload(t.Context()); err != nil {
			t.Fatal(err)
		}
		h.wantLogoutRefused(later, form(captured), reasonLogoutReplayed)
	})
	t.Run("after it expired", func(t *testing.T) {
		h.t = t
		// Past exp (2 minutes) and past the replay cache's memory of the
		// jti: the token is refused for its age instead.
		h.clk.Advance(11 * time.Minute)
		br := h.browser()
		br.loginOIDC("alice", "alice-pass", "")
		h.wantLogoutRefused(br, form(captured), "logout_token_expired")
	})
	h.t = t

	// Many copies of one token at once: exactly one is accepted.
	victim := h.browser()
	victim.loginOIDC("alice", "alice-pass", "")
	tok := h.signLogout("logout+jwt", h.logoutClaims("alice", ""))
	const n = 16
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req, _ := http.NewRequest(http.MethodPost, h.public+"/backchannel-logout/corp", strings.NewReader(form(tok)))
			req.Header.Set("Content-Type", formType)
			resp, err := h.pub.Client().Do(req)
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}()
	}
	before := h.auditCount("logout_rejected", reasonLogoutReplayed)
	close(start)
	wg.Wait()
	ok, refused := 0, 0
	for _, c := range codes {
		switch c {
		case 200:
			ok++
		case 400:
			refused++
		}
	}
	if ok != 1 || refused != n-1 {
		t.Fatalf("concurrent copies: %d accepted, %d refused (%v)", ok, refused, codes)
	}
	if got := h.auditCount("logout_rejected", reasonLogoutReplayed) - before; got != n-1 {
		t.Fatalf("%d replays audited, want %d", got, n-1)
	}
	if victim.auth("/", nil).StatusCode == 200 {
		t.Fatal("the accepted copy ended nothing")
	}
}

// jtiOf reads a token's jti without verifying it.
func jtiOf(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct{ JTI string }
	if err := json.Unmarshal(raw, &c); err != nil || c.JTI == "" {
		t.Fatalf("no jti in %s", raw)
	}
	return c.JTI
}

// TestBackchannelLogoutAudienceAttacks posts tokens the provider really
// signed, meant for someone else: another client, another issuer at the
// same provider, or this client among parties it doesn't trust.
func TestBackchannelLogoutAudienceAttacks(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	br := h.browser()
	br.loginOIDC("alice", "alice-pass", "")
	sid := h.idp.Sessions("alice")[0]
	with := func(f func(c map[string]any)) string {
		c := h.logoutClaims("alice", sid)
		f(c)
		return h.signLogout("logout+jwt", c)
	}
	for _, tc := range []struct{ name, tok, reason string }{
		{"another client", with(func(c map[string]any) { c["aud"] = "another-client" }), "logout_token_wrong_audience"},
		{"no audience", with(func(c map[string]any) { delete(c, "aud") }), "logout_token_wrong_audience"},
		{"empty audience", with(func(c map[string]any) { c["aud"] = "" }), "logout_token_wrong_audience"},
		{"empty audience list", with(func(c map[string]any) { c["aud"] = []string{} }), "logout_token_wrong_audience"},
		{"client id in another case", with(func(c map[string]any) { c["aud"] = "Wicket" }), "logout_token_wrong_audience"},
		{"client id with a space", with(func(c map[string]any) { c["aud"] = "wicket " }), "logout_token_wrong_audience"},
		{"the issuer as audience", with(func(c map[string]any) { c["aud"] = h.idp.Issuer() }), "logout_token_wrong_audience"},
		{"the logout endpoint as audience", with(func(c map[string]any) { c["aud"] = h.public + "/backchannel-logout/corp" }), "logout_token_wrong_audience"},
		{"audience not a string", with(func(c map[string]any) { c["aud"] = 7 }), "logout_token_claims_invalid"},
		{"this client among untrusted ones", with(func(c map[string]any) {
			c["aud"], c["azp"] = []string{"wicket", "another-client"}, "wicket"
		}), "logout_token_wrong_audience"},
		{"another client first, this one second", with(func(c map[string]any) {
			c["aud"], c["azp"] = []string{"another-client", "wicket"}, "another-client"
		}), "logout_token_wrong_audience"},
		{"authorized party another client", with(func(c map[string]any) { c["azp"] = "another-client" }), "logout_token_wrong_authorized_party"},
		{"another issuer at the same provider", with(func(c map[string]any) { c["iss"] = h.idp.Issuer() + "/tenants/other" }), "logout_token_wrong_issuer"},
		{"issuer with a trailing slash", with(func(c map[string]any) { c["iss"] = h.idp.Issuer() + "/" }), "logout_token_wrong_issuer"},
		{"no issuer", with(func(c map[string]any) { delete(c, "iss") }), "logout_token_wrong_issuer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.t = t
			h.wantLogoutRefused(br, form(tc.tok), tc.reason)
		})
	}
	h.t = t
	// None of them used up the jti of a good token, and the good one
	// still works.
	if code, _, _ := h.postLogout("/backchannel-logout/corp", formType, form(with(func(map[string]any) {}))); code != 200 ||
		br.auth("/", nil).StatusCode == 200 {
		t.Fatal("a good token did not end the session after the attacks")
	}
}

// TestBackchannelLogoutEventsAttacks posts tokens the provider really
// signed that are not logout tokens: no events claim, another event, the
// event in the wrong shape, an ID token without a nonce (a refreshed one),
// and a security event token carrying the logout event.
func TestBackchannelLogoutEventsAttacks(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	br := h.browser()
	br.loginOIDC("alice", "alice-pass", "")
	sid := h.idp.Sessions("alice")[0]
	events := func(v any) string {
		c := h.logoutClaims("alice", sid)
		c["events"] = v
		return h.signLogout("logout+jwt", c)
	}
	noEvents := h.logoutClaims("alice", sid)
	delete(noEvents, "events")
	now := h.clk.Now()
	refreshedIDToken := map[string]any{"iss": h.idp.Issuer(), "aud": "wicket", "sub": "alice", "sid": sid,
		"jti": randomHex(t), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Unix(), "email": "alice@example.org"}
	for _, tc := range []struct{ name, tok, reason string }{
		{"no events claim", h.signLogout("logout+jwt", noEvents), "logout_token_no_event"},
		{"events null", events(nil), "logout_token_no_event"},
		{"events empty", events(map[string]any{}), "logout_token_no_event"},
		{"events a list of the event", events([]string{backchannelEvent}), "logout_token_no_event"},
		{"events the event's name", events(backchannelEvent), "logout_token_no_event"},
		{"front-channel logout event", events(map[string]any{"http://schemas.openid.net/event/front-channel-logout": map[string]any{}}), "logout_token_no_event"},
		{"session revoked (CAEP)", events(map[string]any{"https://schemas.openid.net/secevent/caep/event-type/session-revoked": map[string]any{}}), "logout_token_no_event"},
		{"account disabled (RISC)", events(map[string]any{"https://schemas.openid.net/secevent/risc/event-type/account-disabled": map[string]any{}}), "logout_token_no_event"},
		{"the event under https", events(map[string]any{"https://schemas.openid.net/event/backchannel-logout": map[string]any{}}), "logout_token_no_event"},
		{"the event with a trailing slash", events(map[string]any{backchannelEvent + "/": map[string]any{}}), "logout_token_no_event"},
		{"the event in upper case", events(map[string]any{strings.ToUpper(backchannelEvent): map[string]any{}}), "logout_token_no_event"},
		{"the event true", events(map[string]any{backchannelEvent: true}), "logout_token_no_event"},
		{"the event a string", events(map[string]any{backchannelEvent: ""}), "logout_token_no_event"},
		{"the event null", events(map[string]any{backchannelEvent: nil}), "logout_token_no_event"},
		{"the event a list", events(map[string]any{backchannelEvent: []any{map[string]any{}}}), "logout_token_no_event"},
		{"a refreshed ID token", h.signLogout("JWT", refreshedIDToken), "logout_token_no_event"},
		{"a security event token with the event", h.signLogout("secevent+jwt", h.logoutClaims("alice", sid)), "logout_token_invalid"},
		{"an access token with the event", h.signLogout("at+jwt", h.logoutClaims("alice", sid)), "logout_token_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.t = t
			h.wantLogoutRefused(br, form(tc.tok), tc.reason)
		})
	}
	h.t = t
	h.wantMetrics(`wicket_backchannel_logouts_total{provider="corp",result="rejected"} 18`)
	if l := h.sessions.List("", 0); len(l) != 1 {
		t.Fatalf("sessions: %+v", l)
	}
}

// Raw query handling for HTTP-Redirect messages: the signature covers the
// parameters exactly as sent, so the attacks work on the raw pairs.

type rawPair struct{ k, v string }

func splitQuery(t *testing.T, target string) (string, []rawPair) {
	t.Helper()
	base, q, ok := strings.Cut(target, "?")
	if !ok {
		t.Fatalf("no query in %s", target)
	}
	var out []rawPair
	for _, p := range strings.Split(q, "&") {
		k, v, _ := strings.Cut(p, "=")
		out = append(out, rawPair{k, v})
	}
	return base, out
}

func joinQuery(base string, pairs []rawPair) string {
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return base + "?" + strings.Join(parts, "&")
}

// editQuery drops the drop parameters and sets the set ones (appended
// when absent).
func editQuery(t *testing.T, target string, set map[string]string, drop ...string) string {
	t.Helper()
	base, pairs := splitQuery(t, target)
	var out []rawPair
	seen := map[string]bool{}
	for _, p := range pairs {
		if contains(drop, p.k) {
			continue
		}
		if v, ok := set[p.k]; ok {
			p.v, seen[p.k] = v, true
		}
		out = append(out, p)
	}
	for _, k := range []string{"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"} {
		if v, ok := set[k]; ok && !seen[k] {
			out = append(out, rawPair{k, v})
		}
	}
	return joinQuery(base, out)
}

func queryParam(t *testing.T, target, k string) string {
	t.Helper()
	_, pairs := splitQuery(t, target)
	for _, p := range pairs {
		if p.k == k {
			return p.v
		}
	}
	t.Fatalf("no %s in %s", k, target)
	return ""
}

// resignRedirect signs a Redirect message's raw parameters again with key
// under alg, as the binding does.
func resignRedirect(t *testing.T, target string, key *rsa.PrivateKey, alg string, hash crypto.Hash) string {
	t.Helper()
	base, pairs := splitQuery(t, target)
	var signed []string
	for _, k := range []string{"SAMLRequest", "SAMLResponse", "RelayState"} {
		for _, p := range pairs {
			if p.k == k {
				signed = append(signed, p.k+"="+p.v)
			}
		}
	}
	signed = append(signed, "SigAlg="+url.QueryEscape(alg))
	in := []byte(strings.Join(signed, "&"))
	var sum []byte
	switch hash {
	case crypto.SHA1:
		s := sha1.Sum(in)
		sum = s[:]
	default:
		s := sha256.Sum256(in)
		sum = s[:]
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, sum)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.Join(signed, "&") + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	return base + "?" + out
}

// deflateParam encodes XML as an HTTP-Redirect parameter value.
func deflateParam(xml []byte) string {
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	fw.Write(xml)
	fw.Close()
	return url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
}

// postDoc decodes an HTTP-POST message.
func postDoc(t *testing.T, form url.Values, param string) *etree.Document {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(form.Get(param))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	return doc
}

// withDoc returns a copy of form whose param holds doc.
func withDoc(t *testing.T, form url.Values, param string, doc *etree.Document) url.Values {
	t.Helper()
	b, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	out := url.Values{}
	for k, v := range form {
		out[k] = append([]string(nil), v...)
	}
	out.Set(param, base64.StdEncoding.EncodeToString(b))
	return out
}

// unsignPOST takes the enveloped signature off an HTTP-POST message.
func unsignPOST(t *testing.T, form url.Values, param string) url.Values {
	t.Helper()
	doc := postDoc(t, form, param)
	sig := doc.Root().SelectElement("Signature")
	if sig == nil {
		t.Fatalf("no signature to take off")
	}
	doc.Root().RemoveChild(sig)
	return withDoc(t, form, param, doc)
}

// TestSAMLSingleLogoutUnsignedAttacks sends logout messages whose signature
// is missing, stripped, moved or no longer covers what is read, on both
// bindings, in both directions. A LogoutRequest that got through would end
// carol's session; a LogoutResponse that got through would finish another
// browser's pending sign-out.
func TestSAMLSingleLogoutUnsignedAttacks(t *testing.T) {
	h := sloHarness(t)
	carolBr := h.browser()
	carolBr.loginSAML("carol", "carol-pass")
	idx := h.idp.SAMLSessions(carol)
	sp := h.public + "/saml/partner/metadata"
	idpKey := h.idp.SigningKey()
	attackerKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// request builds the IdP's LogoutRequest for carol's session.
	request := func(o fakeidp.SAMLLogoutOptions) (string, url.Values, string) {
		t.Helper()
		o.SP, o.NameID, o.SessionIndex = sp, carol, idx
		target, form, id, err := h.idp.SAMLLogoutRequest(o)
		if err != nil {
			t.Fatal(err)
		}
		return target, form, id
	}
	redirect := func(o fakeidp.SAMLLogoutOptions) string { u, _, _ := request(o); return u }
	post := func(o fakeidp.SAMLLogoutOptions) (string, url.Values) {
		o.Binding = fakeidp.POST
		u, f, _ := request(o)
		return u, f
	}
	_, signedPOST := post(fakeidp.SAMLLogoutOptions{})
	signedXML, _ := base64.StdEncoding.DecodeString(signedPOST.Get("SAMLRequest"))
	unsignedRedirect := redirect(fakeidp.SAMLLogoutOptions{Unsigned: true})
	// A genuine, signed request about nobody: its signature is real.
	nobody, _, _, _ := h.idp.SAMLLogoutRequest(fakeidp.SAMLLogoutOptions{SP: sp, NameID: "nobody@partner.example"})

	type attack struct {
		name   string
		get    string     // a Redirect URL to GET, or
		form   url.Values // a POST form for the SingleLogoutService
		reason string
	}
	attacks := []attack{
		// HTTP-Redirect.
		{name: "redirect: unsigned", get: unsignedRedirect, reason: "signature_missing"},
		{name: "redirect: Signature taken off", get: editQuery(t, redirect(fakeidp.SAMLLogoutOptions{}), nil, "Signature"), reason: "signature_missing"},
		{name: "redirect: SigAlg taken off", get: editQuery(t, redirect(fakeidp.SAMLLogoutOptions{}), nil, "SigAlg"), reason: "signature_missing"},
		{name: "redirect: empty Signature", get: editQuery(t, redirect(fakeidp.SAMLLogoutOptions{}), map[string]string{"Signature": ""}), reason: "signature_invalid"},
		{name: "redirect: empty SigAlg", get: editQuery(t, redirect(fakeidp.SAMLLogoutOptions{}), map[string]string{"SigAlg": ""}), reason: "signature_invalid"},
		{name: "redirect: SigAlg changed to SHA-512", get: editQuery(t, redirect(fakeidp.SAMLLogoutOptions{}),
			map[string]string{"SigAlg": url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")}), reason: "signature_invalid"},
		{name: "redirect: SigAlg changed to ECDSA", get: editQuery(t, redirect(fakeidp.SAMLLogoutOptions{}),
			map[string]string{"SigAlg": url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")}), reason: "signature_invalid"},
		{name: "redirect: signed with the IdP's key under SHA-1", get: resignRedirect(t, unsignedRedirect, idpKey,
			"http://www.w3.org/2000/09/xmldsig#rsa-sha1", crypto.SHA1), reason: "signature_invalid"},
		{name: "redirect: signed by the attacker", get: redirect(fakeidp.SAMLLogoutOptions{SignWithOther: attackerKey}), reason: "signature_invalid"},
		{name: "redirect: RelayState added after signing", get: editQuery(t, redirect(fakeidp.SAMLLogoutOptions{}),
			map[string]string{"RelayState": "evil"}), reason: "signature_invalid"},
		{name: "redirect: RelayState taken off after signing", get: editQuery(t, redirect(fakeidp.SAMLLogoutOptions{RelayState: "idp-state"}),
			nil, "RelayState"), reason: "signature_invalid"},
		{name: "redirect: another request under a real signature", get: editQuery(t, nobody,
			map[string]string{"SAMLRequest": queryParam(t, unsignedRedirect, "SAMLRequest")}), reason: "signature_invalid"},
		{name: "redirect: the signed request repeated, unsigned one read", get: editQuery(t, nobody,
			map[string]string{"SAMLRequest": queryParam(t, nobody, "SAMLRequest") + "&SAMLRequest=" + queryParam(t, unsignedRedirect, "SAMLRequest")}),
			reason: "malformed_response"},
		{name: "redirect: an XML-signed request without a query signature", get: h.public + "/saml/partner/slo?SAMLRequest=" + deflateParam(signedXML),
			reason: "signature_missing"},
		{name: "redirect: an XML-signed request under the query signature of another", get: editQuery(t, nobody,
			map[string]string{"SAMLRequest": deflateParam(signedXML)}), reason: "signature_invalid"},

		// HTTP-POST.
		{name: "POST: unsigned", form: func() url.Values { _, f := post(fakeidp.SAMLLogoutOptions{Unsigned: true}); return f }(), reason: "signature_missing"},
		{name: "POST: signature taken off", form: func() url.Values {
			_, f := post(fakeidp.SAMLLogoutOptions{})
			return unsignPOST(t, f, "SAMLRequest")
		}(), reason: "signature_missing"},
		{name: "POST: signed by the attacker", form: func() url.Values {
			_, f := post(fakeidp.SAMLLogoutOptions{SignWithOther: attackerKey})
			return f
		}(), reason: "signature_invalid"},
		{name: "POST: NameID changed after signing", form: func() url.Values {
			_, f, _, _ := h.idp.SAMLLogoutRequest(fakeidp.SAMLLogoutOptions{SP: sp, NameID: "nobody@partner.example", Binding: fakeidp.POST})
			doc := postDoc(t, f, "SAMLRequest")
			doc.Root().SelectElement("NameID").SetText(carol)
			return withDoc(t, f, "SAMLRequest", doc)
		}(), reason: "signature_invalid"},
		{name: "POST: SessionIndex added after signing", form: func() url.Values {
			_, f, _, _ := h.idp.SAMLLogoutRequest(fakeidp.SAMLLogoutOptions{SP: sp, NameID: carol, SessionIndex: []string{"_other"}, Binding: fakeidp.POST})
			doc := postDoc(t, f, "SAMLRequest")
			s := doc.Root().CreateElement("samlp:SessionIndex")
			s.SetText(idx[0])
			return withDoc(t, f, "SAMLRequest", doc)
		}(), reason: "signature_invalid"},
		{name: "POST: signed request wrapped in an unsigned one", form: func() url.Values {
			// The IdP's signed request about nobody rides inside an
			// unsigned request about carol with the same ID: only a
			// signature on the message itself counts.
			_, f, _, _ := h.idp.SAMLLogoutRequest(fakeidp.SAMLLogoutOptions{SP: sp, NameID: "nobody@partner.example", Binding: fakeidp.POST})
			signed := postDoc(t, f, "SAMLRequest").Root()
			_, uf := post(fakeidp.SAMLLogoutOptions{Unsigned: true})
			evil := postDoc(t, uf, "SAMLRequest")
			evil.Root().RemoveAttr("ID")
			evil.Root().CreateAttr("ID", signed.SelectAttrValue("ID", ""))
			ext := evil.Root().CreateElement("samlp:Extensions")
			ext.AddChild(signed)
			return withDoc(t, uf, "SAMLRequest", evil)
		}(), reason: "signature_missing"},
		// Its Reference names the other request's ID.
		{name: "POST: the signature moved from another request", form: func() url.Values {
			_, f, _, _ := h.idp.SAMLLogoutRequest(fakeidp.SAMLLogoutOptions{SP: sp, NameID: "nobody@partner.example", Binding: fakeidp.POST})
			sig := postDoc(t, f, "SAMLRequest").Root().SelectElement("Signature")
			_, uf := post(fakeidp.SAMLLogoutOptions{Unsigned: true})
			evil := postDoc(t, uf, "SAMLRequest")
			evil.Root().InsertChildAt(1, sig)
			return withDoc(t, uf, "SAMLRequest", evil)
		}(), reason: "signature_wrapping"},
		{name: "POST: a query signature instead of an XML one", form: func() url.Values {
			_, uf := post(fakeidp.SAMLLogoutOptions{Unsigned: true})
			// The fields of a real Redirect signature, carried in the form.
			uf.Set("SigAlg", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
			s, _ := url.QueryUnescape(queryParam(t, nobody, "Signature"))
			uf.Set("Signature", s)
			return uf
		}(), reason: "signature_missing"},
	}

	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			h.t = t
			before := h.auditCount("logout_rejected", a.reason)
			var resp *http.Response
			var body string
			attacker := h.browser()
			if a.get != "" {
				resp, body = attacker.get(a.get)
			} else {
				resp, body = attacker.post(h.public+"/saml/partner/slo", a.form)
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%d %s\n%s", resp.StatusCode, resp.Header.Get("Location"), body)
			}
			if got := h.auditCount("logout_rejected", a.reason); got != before+1 {
				t.Fatalf("audited %d refusals for %s, want %d\nlogs:\n%s", got, a.reason, before+1, lastLines(h.logs.String(), 2))
			}
			if c := carolBr.auth("/", nil).StatusCode; c != 200 {
				t.Fatalf("carol was signed out: %d", c)
			}
		})
	}
	h.t = t
	if len(h.idp.SAMLSessions(carol)) != 1 {
		t.Fatal("the IdP's own session changed")
	}
	h.wantMetrics(fmt.Sprintf(`wicket_saml_logouts_total{provider="partner",initiator="",result="rejected"} %d`, len(attacks)))
	// The genuine, signed request still works afterwards.
	resp, _ := h.browser().get(redirect(fakeidp.SAMLLogoutOptions{}))
	if resp.StatusCode != http.StatusSeeOther || carolBr.auth("/", nil).StatusCode != 401 {
		t.Fatalf("the genuine request after the attacks: %d", resp.StatusCode)
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// TestSAMLSingleLogoutUnsignedResponse strips the signature off the IdP's
// LogoutResponse to an SP-initiated sign-out, on each binding. It is
// refused before the pending sign-out is looked at, so the genuine answer
// still completes it.
func TestSAMLSingleLogoutUnsignedResponse(t *testing.T) {
	for _, binding := range []string{fakeidp.Redirect, fakeidp.POST} {
		t.Run(binding, func(t *testing.T) {
			h := sloHarness(t, binding)
			b := h.browser()
			b.loginSAML("carol", "carol-pass")
			resp, body := b.signOut()
			answer, answerBody := b.follow(resp, body) // the IdP's signed LogoutResponse
			before := h.auditCount("logout_rejected", "signature_missing")

			var forged *http.Response
			switch binding {
			case fakeidp.Redirect:
				loc := answer.Header.Get("Location")
				if (answer.StatusCode != http.StatusFound && answer.StatusCode != http.StatusSeeOther) || !strings.Contains(loc, "SAMLResponse=") {
					t.Fatalf("IdP answer: %d %s", answer.StatusCode, loc)
				}
				forged, _ = b.get(editQuery(t, loc, nil, "SigAlg", "Signature"))
				if r, _ := b.get(resignRedirect(t, editQuery(t, loc, nil, "SigAlg", "Signature"), h.idp.SigningKey(),
					"http://www.w3.org/2000/09/xmldsig#rsa-sha1", crypto.SHA1)); r.StatusCode != http.StatusBadRequest {
					t.Fatalf("SHA-1 answer: %d", r.StatusCode)
				}
				h.expectAudit("logout_rejected", "signature_invalid")
				answer, _ = b.get(loc)
			case fakeidp.POST:
				action, fields := formFields(answerBody)
				if answer.StatusCode != 200 || fields.Get("SAMLResponse") == "" {
					t.Fatalf("IdP answer: %d %s", answer.StatusCode, answerBody)
				}
				forged, _ = b.post(action, unsignPOST(t, fields, "SAMLResponse"))
				answer, _ = b.post(action, fields)
			}
			if forged.StatusCode != http.StatusBadRequest {
				t.Fatalf("unsigned answer: %d", forged.StatusCode)
			}
			if got := h.auditCount("logout_rejected", "signature_missing"); got != before+1 {
				t.Fatalf("audited %d, want %d", got, before+1)
			}
			if answer.StatusCode != http.StatusSeeOther || answer.Header.Get("Location") != h.public+"/logged-out" {
				t.Fatalf("the genuine answer after the forged one: %d %s", answer.StatusCode, answer.Header.Get("Location"))
			}
			h.wantMetrics(`wicket_saml_logouts_total{provider="partner",initiator="sp",result="accepted"} 1`)
		})
	}
}
