// Package policy decides whether an authenticated identity may use an app.
// Everything is denied unless a rule allows it.
package policy

import (
	"strings"
)

// Identity is what the gateway knows about a signed-in user.
type Identity struct {
	Provider string   `json:"provider"`
	Subject  string   `json:"sub"`
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	// Claims are the sign-in's other claims or SAML attributes, by name,
	// for claim conditions (see ClaimCondition).
	Claims map[string][]string `json:"claims,omitempty"`
}

// Rule is an app's access policy. A user is allowed when they signed in with
// one of Providers AND every claim condition holds AND at least one of the
// allow conditions holds. A rule with claim conditions and no allow
// conditions allows every user of its providers who meets them. An empty
// rule allows nobody.
type Rule struct {
	Providers    []string // identity providers accepted for the app
	AnyUser      bool     // every user of an accepted provider
	Emails       []string // exact addresses, compared case-insensitively
	EmailDomains []string // the part after '@', compared case-insensitively
	Groups       []string // exact, case-sensitive group names
	Claims       []ClaimCondition
}

// Reason codes returned by Evaluate.
const (
	Allowed         = "allowed"
	DeniedProvider  = "provider_not_accepted"
	DeniedNoMatch   = "no_rule_matched"
	DeniedNoSubject = "no_subject"
)

// Compiled is a Rule prepared for fast evaluation.
type Compiled struct {
	providers map[string]bool
	anyUser   bool
	emails    map[string]bool
	domains   map[string]bool
	groups    map[string]bool
	claims    []claimCond
	badClaims bool // the claim conditions did not compile: nobody is allowed
}

// Compile normalizes a rule. Its claim conditions are checked by
// CompileApp; a rule whose conditions do not compile allows nobody.
func Compile(r Rule) *Compiled {
	claims, err := compileClaims(r.Claims)
	lists := r.AnyUser || len(r.Emails)+len(r.EmailDomains)+len(r.Groups) > 0
	c := &Compiled{providers: set(r.Providers, false), anyUser: r.AnyUser || (len(claims) > 0 && !lists),
		emails: set(r.Emails, true), domains: set(r.EmailDomains, true), groups: set(r.Groups, false),
		claims: claims, badClaims: err != nil}
	return c
}

func set(list []string, fold bool) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, v := range list {
		if fold {
			v = strings.ToLower(v)
		}
		m[v] = true
	}
	return m
}

// Evaluate returns whether id may use the app, and a reason code.
func (c *Compiled) Evaluate(id Identity) (bool, string) {
	if id.Subject == "" {
		return false, DeniedNoSubject
	}
	if !c.providers[id.Provider] {
		return false, DeniedProvider
	}
	if c.badClaims {
		return false, DeniedNoMatch
	}
	if len(c.claims) > 0 && !claimsHold(c.claims, &id) {
		return false, DeniedClaims
	}
	if c.anyUser {
		return true, Allowed
	}
	if email := strings.ToLower(id.Email); email != "" {
		if c.emails[email] {
			return true, Allowed
		}
		if at := strings.LastIndexByte(email, '@'); at > 0 && c.domains[email[at+1:]] {
			return true, Allowed
		}
	}
	for _, g := range id.Groups {
		if c.groups[g] {
			return true, Allowed
		}
	}
	return false, DeniedNoMatch
}
