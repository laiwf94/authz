package saml

import (
	"reflect"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// withAttrs adds attributes to the assertion before the IdP signs it.
func withAttrs(attrs map[string][]string) func(a *etree.Element) {
	return func(a *etree.Element) {
		st := a.FindElement("./AttributeStatement")
		for name, values := range attrs {
			at := st.CreateElement("saml:Attribute")
			at.CreateAttr("Name", name)
			for _, v := range values {
				at.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
}

func TestResponseKeepsNamedAttributes(t *testing.T) {
	e := newEnv(t)
	sp := e.newSP(func(c *Config) { c.Claims = []string{"department", "clearance", "absent"} })
	attrs := withAttrs(map[string][]string{
		"department":  {"eng", "ops", "eng"},
		"clearance":   {"level-2"},
		"secret_attr": {"never kept"},
	})
	res, err := sp.ParseResponse(encode(t, e.doc(respOpts{signAssertion: true, beforeSign: attrs})), reqID)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"department": {"eng", "ops"}, "clearance": {"level-2"}}
	if !reflect.DeepEqual(res.Identity.Claims, want) {
		t.Errorf("claims %v, want %v", res.Identity.Claims, want)
	}
	// The mapped attributes still fill the identity.
	if res.Identity.Email != "carol@partner.example" || len(res.Identity.Groups) != 1 {
		t.Errorf("identity %+v", res.Identity)
	}

	// An SP that names none keeps none.
	res, err = e.sp.ParseResponse(encode(t, e.doc(respOpts{signAssertion: true, beforeSign: attrs})), reqID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Identity.Claims != nil {
		t.Errorf("claims kept without names: %v", res.Identity.Claims)
	}

	// Encrypted assertions carry them too.
	res, err = sp.ParseResponse(encode(t, e.doc(respOpts{signAssertion: true, encrypt: true,
		beforeSign: withAttrs(map[string][]string{"clearance": {"level-3"}})})), reqID)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Identity.Claims["clearance"]; !reflect.DeepEqual(got, []string{"level-3"}) {
		t.Errorf("encrypted: clearance %v", got)
	}
}

func TestResponseRefusesUnkeepableAttributes(t *testing.T) {
	e := newEnv(t)
	names := make([]string, 0, 70)
	many := map[string][]string{}
	for i := 0; i < 70; i++ {
		n := "a" + strings.Repeat("x", i)
		names = append(names, n)
		many[n] = []string{"v"}
	}
	sp := e.newSP(func(c *Config) { c.Claims = names })
	_, err := sp.ParseResponse(encode(t, e.doc(respOpts{signAssertion: true, beforeSign: withAttrs(many)})), reqID)
	if reasonOf(err) != ReasonAttributes || !strings.Contains(err.Error(), "more than 64 claims") {
		t.Errorf("70 named attributes: %v", err)
	}
}
