package policy

import (
	"errors"
	"fmt"
)

// ClaimCondition is a condition on one claim of the sign-in: an OpenID
// Connect ID token claim or a SAML attribute. Exactly one operator is set:
//
//   - Equals: some value of the claim is exactly this string;
//   - In: some value of the claim is one of these strings (membership);
//   - Matches: some value of the claim matches this pattern, where '*'
//     stands for any run of bytes (empty included), '?' for exactly one
//     byte, and '\' makes the byte after it literal ("\*" is a '*').
//
// Comparisons are exact and case-sensitive. A claim can have several
// values (a SAML attribute, a JSON array claim); the condition holds when
// any of them satisfies it, and never when the claim is absent.
//
// The names sub, idp, email, name and groups always read the identity the
// gateway verified (Identity's Subject, Provider, Email, Name and Groups);
// every other name reads Identity.Claims.
type ClaimCondition struct {
	Claim   string
	Equals  string
	In      []string
	Matches string
}

// Limits on claim conditions, checked when a policy is compiled.
const (
	MaxClaimConditions = 16   // per rule
	MaxClaimIn         = 256  // values of one In
	MaxClaimValueBytes = 1024 // an Equals or In value, or a Matches pattern
	maxClaimNameBytes  = 256
)

// DeniedClaims is the reason code when the identity is accepted but a
// claim condition of the rule does not hold.
const DeniedClaims = "claims_not_matched"

type claimSource uint8

const (
	claimOther claimSource = iota
	claimSub
	claimIdP
	claimEmail
	claimName
	claimGroups
)

type claimOp uint8

const (
	opEquals claimOp = iota
	opIn
	opMatches
)

type claimCond struct {
	name   string
	src    claimSource
	op     claimOp
	equals string
	in     map[string]struct{}
	glob   []globTok
}

// compileClaims checks a rule's claim conditions. Every problem is
// reported, each naming the condition ("claims[2]").
func compileClaims(list []ClaimCondition) ([]claimCond, error) {
	if len(list) == 0 {
		return nil, nil
	}
	if len(list) > MaxClaimConditions {
		return nil, fmt.Errorf("claims: at most %d conditions, not %d", MaxClaimConditions, len(list))
	}
	var errs []error
	out := make([]claimCond, 0, len(list))
	for i, c := range list {
		cc, err := compileClaim(c)
		if err != nil {
			errs = append(errs, fmt.Errorf("claims[%d]: %w", i, err))
			continue
		}
		out = append(out, cc)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

func compileClaim(c ClaimCondition) (claimCond, error) {
	cc := claimCond{name: c.Claim}
	if c.Claim == "" || len(c.Claim) > maxClaimNameBytes {
		return cc, fmt.Errorf("a claim name is 1 to %d bytes", maxClaimNameBytes)
	}
	for i := 0; i < len(c.Claim); i++ {
		if c.Claim[i] < 0x21 || c.Claim[i] >= 0x7f {
			return cc, fmt.Errorf("claim name %q may only contain visible ASCII", c.Claim)
		}
	}
	switch c.Claim {
	case "sub":
		cc.src = claimSub
	case "idp":
		cc.src = claimIdP
	case "email":
		cc.src = claimEmail
	case "name":
		cc.src = claimName
	case "groups":
		cc.src = claimGroups
	}
	n := 0
	if c.Equals != "" {
		n++
	}
	if len(c.In) > 0 {
		n++
	}
	if c.Matches != "" {
		n++
	}
	if n != 1 {
		return cc, fmt.Errorf("claim %q: give exactly one of equals, in or matches", c.Claim)
	}
	switch {
	case c.Equals != "":
		if len(c.Equals) > MaxClaimValueBytes {
			return cc, fmt.Errorf("claim %q: a value is at most %d bytes", c.Claim, MaxClaimValueBytes)
		}
		cc.op, cc.equals = opEquals, c.Equals
	case len(c.In) > 0:
		if len(c.In) > MaxClaimIn {
			return cc, fmt.Errorf("claim %q: in lists at most %d values, not %d", c.Claim, MaxClaimIn, len(c.In))
		}
		cc.op, cc.in = opIn, make(map[string]struct{}, len(c.In))
		for _, v := range c.In {
			if v == "" || len(v) > MaxClaimValueBytes {
				return cc, fmt.Errorf("claim %q: an in value is 1 to %d bytes", c.Claim, MaxClaimValueBytes)
			}
			if _, dup := cc.in[v]; dup {
				return cc, fmt.Errorf("claim %q: in lists %q twice", c.Claim, v)
			}
			cc.in[v] = struct{}{}
		}
	default:
		if len(c.Matches) > MaxClaimValueBytes {
			return cc, fmt.Errorf("claim %q: a pattern is at most %d bytes", c.Claim, MaxClaimValueBytes)
		}
		g, err := compileGlob(c.Matches)
		if err != nil {
			return cc, fmt.Errorf("claim %q: %w", c.Claim, err)
		}
		cc.op, cc.glob = opMatches, g
	}
	return cc, nil
}

// holds says whether the condition holds for id. It allocates nothing.
func (c *claimCond) holds(id *Identity) bool {
	switch c.src {
	case claimSub:
		return c.test(id.Subject)
	case claimIdP:
		return c.test(id.Provider)
	case claimEmail:
		return c.test(id.Email)
	case claimName:
		return c.test(id.Name)
	case claimGroups:
		return c.any(id.Groups)
	}
	return c.any(id.Claims[c.name])
}

func (c *claimCond) any(values []string) bool {
	for _, v := range values {
		if c.test(v) {
			return true
		}
	}
	return false
}

// test checks one value; an empty value is an absent one.
func (c *claimCond) test(v string) bool {
	if v == "" {
		return false
	}
	switch c.op {
	case opEquals:
		return v == c.equals
	case opIn:
		_, ok := c.in[v]
		return ok
	}
	return globMatch(c.glob, v)
}

// claimsHold says whether every condition holds.
func claimsHold(conds []claimCond, id *Identity) bool {
	for i := range conds {
		if !conds[i].holds(id) {
			return false
		}
	}
	return true
}

type globKind uint8

const (
	globLit  globKind = iota // lit bytes
	globOne                  // '?': one byte
	globStar                 // '*': any run of bytes
)

type globTok struct {
	kind globKind
	lit  string
}

// compileGlob splits a pattern into literal runs, '?' and '*', with
// repeated stars folded into one.
func compileGlob(p string) ([]globTok, error) {
	var toks []globTok
	var lit []byte
	flush := func() {
		if len(lit) > 0 {
			toks = append(toks, globTok{kind: globLit, lit: string(lit)})
			lit = lit[:0]
		}
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '\\':
			if i+1 == len(p) {
				return nil, fmt.Errorf("pattern %q ends in a lone '\\'", p)
			}
			i++
			lit = append(lit, p[i])
		case '*':
			flush()
			if n := len(toks); n == 0 || toks[n-1].kind != globStar {
				toks = append(toks, globTok{kind: globStar})
			}
		case '?':
			flush()
			toks = append(toks, globTok{kind: globOne})
		default:
			lit = append(lit, c)
		}
	}
	flush()
	return toks, nil
}

// globMatch matches v against compiled tokens. On a mismatch it goes back
// to the most recent star and lets it take one more byte, which is enough
// because a star can absorb anything a later star could: the time is at
// most len(v) times the pattern's length, and nothing is allocated.
func globMatch(toks []globTok, v string) bool {
	ti, vi := 0, 0
	star, starV := -1, 0
	for {
		if ti < len(toks) {
			t := toks[ti]
			switch t.kind {
			case globStar:
				star, starV = ti, vi
				ti++
				continue
			case globOne:
				if vi < len(v) {
					ti++
					vi++
					continue
				}
			case globLit:
				if len(v)-vi >= len(t.lit) && v[vi:vi+len(t.lit)] == t.lit {
					ti++
					vi += len(t.lit)
					continue
				}
			}
		} else if vi == len(v) {
			return true
		}
		if star < 0 || starV >= len(v) {
			return false
		}
		starV++
		ti, vi = star+1, starV
	}
}
