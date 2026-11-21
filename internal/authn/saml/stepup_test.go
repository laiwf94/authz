package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/laiwf94/authz/internal/authn/fakeidp"
)

// TestAuthnRequestStepUp: a step-up asks for a fresh authentication with
// ForceAuthn and for its classes with an exact RequestedAuthnContext after
// the NameIDPolicy, as the schema orders them; an ordinary request has
// neither.
func TestAuthnRequestStepUp(t *testing.T) {
	e := newEnv(t)
	decode := func(u string) *etree.Element {
		t.Helper()
		pu, _ := url.Parse(u)
		raw, _ := base64.StdEncoding.DecodeString(pu.Query().Get("SAMLRequest"))
		b, _ := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(b); err != nil {
			t.Fatal(err)
		}
		return doc.Root()
	}
	plain, _ := e.sp.AuthnRequestURL(reqID, "r")
	if r := decode(plain); r.SelectAttr("ForceAuthn") != nil || find(r, "RequestedAuthnContext") != nil {
		t.Fatal("an ordinary request asks for a step-up")
	}
	u, err := e.sp.AuthnRequestURLWith(reqID, "r", AuthnOptions{ForceAuthn: true, ClassRefs: []string{"urn:mfa", "urn:hwk"}})
	if err != nil {
		t.Fatal(err)
	}
	r := decode(u)
	if r.SelectAttrValue("ForceAuthn", "") != "true" {
		t.Fatal("no ForceAuthn")
	}
	kids := r.ChildElements()
	last := kids[len(kids)-1]
	if last.Tag != "RequestedAuthnContext" || last.NamespaceURI() != NSProtocol || kids[len(kids)-2].Tag != "NameIDPolicy" ||
		last.SelectAttrValue("Comparison", "") != "exact" {
		t.Fatalf("RequestedAuthnContext misplaced: %v", kids)
	}
	refs := last.ChildElements()
	if len(refs) != 2 || refs[0].Text() != "urn:mfa" || refs[1].Text() != "urn:hwk" || refs[0].NamespaceURI() != NSAssertion {
		t.Fatalf("class refs %v", refs)
	}
	if r := decode(mustURL(t, e.sp, AuthnOptions{ClassRefs: []string{"urn:mfa"}})); r.SelectAttr("ForceAuthn") != nil {
		t.Fatal("a class-only step-up forces authentication")
	}
}

func mustURL(t *testing.T, sp *SP, o AuthnOptions) string {
	t.Helper()
	u, err := sp.AuthnRequestURLWith(reqID, "", o)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestAuthnStatementContext: AuthnInstant and AuthnContextClassRef come
// back with the identity; a malformed one fails the login.
func TestAuthnStatementContext(t *testing.T) {
	e := newEnv(t)
	at := e.clk.now().Add(-90 * time.Second).UTC().Truncate(time.Second)
	parse := func(o fakeidp.ResponseOptions) (*Result, error) {
		o.SP = fakeidp.ServiceProvider{EntityID: spEntity, ACSURL: acsURL, SignAssertion: true}
		o.InResponseTo, o.User = reqID, fakeidp.DemoUsers[2]
		doc, err := e.idp.SAMLResponseDoc(o)
		if err != nil {
			t.Fatal(err)
		}
		return e.sp.ParseResponse(encode(t, doc), reqID)
	}
	res, err := parse(fakeidp.ResponseOptions{AuthnInstant: at, ClassRef: fakeidp.ACRMFA})
	if err != nil {
		t.Fatal(err)
	}
	if !res.AuthnInstant.Equal(at) || res.AuthnContextClassRef != fakeidp.ACRMFA {
		t.Fatalf("got %v %q", res.AuthnInstant, res.AuthnContextClassRef)
	}
	res, err = parse(fakeidp.ResponseOptions{})
	if err != nil || res.AuthnContextClassRef != "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" || res.AuthnInstant.IsZero() {
		t.Fatalf("default: %+v %v", res, err)
	}
	statement := func(f func(as *etree.Element)) func(a *etree.Element) {
		return func(a *etree.Element) { f(find(a, "AuthnStatement")) }
	}
	for _, c := range []struct {
		name   string
		mutate func(as *etree.Element)
		reason string
		check  func(r *Result) bool
	}{
		{"no AuthnInstant", func(as *etree.Element) { as.RemoveAttr("AuthnInstant") }, "",
			func(r *Result) bool { return r.AuthnInstant.IsZero() }},
		{"no AuthnContext", func(as *etree.Element) { as.RemoveChild(find(as, "AuthnContext")) }, "",
			func(r *Result) bool { return r.AuthnContextClassRef == "" }},
		{"class ref padded", func(as *etree.Element) { find(as, "AuthnContextClassRef").SetText("\n  urn:mfa \n") }, "",
			func(r *Result) bool { return r.AuthnContextClassRef == "urn:mfa" }},
		{"bad AuthnInstant", func(as *etree.Element) { as.CreateAttr("AuthnInstant", "yesterday") }, ReasonMalformed, nil},
		{"class ref with a space", func(as *etree.Element) { find(as, "AuthnContextClassRef").SetText("two words") }, ReasonMalformed, nil},
		{"empty class ref", func(as *etree.Element) { find(as, "AuthnContextClassRef").SetText("") }, ReasonMalformed, nil},
	} {
		res, err := parse(fakeidp.ResponseOptions{BeforeSign: statement(c.mutate)})
		if c.reason != "" {
			if reasonOf(err) != c.reason {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err != nil || !c.check(res) {
			t.Errorf("%s: %+v %v", c.name, res, err)
		}
	}
}
