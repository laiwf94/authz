package policy

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"unicode/utf8"
)

// Limits on the claims a session keeps for claim conditions (the claims
// of Identity.Claims), checked by CleanClaims at sign-in and by CheckClaims
// wherever an identity comes from outside.
const (
	MaxSessionClaims      = 64       // claim names
	MaxSessionClaimValues = 256      // values of one claim
	MaxSessionClaimBytes  = 16 << 10 // every name and value together
)

// ClaimNames returns the claims the policy's claim conditions read from
// Identity.Claims, sorted: every condition's claim except sub, idp, email,
// name and groups, which read the verified identity. A sign-in keeps
// these claims and no others.
func (p *Policy) ClaimNames() []string {
	seen := map[string]struct{}{}
	add := func(c *Compiled) {
		if c == nil {
			return
		}
		for i := range c.claims {
			if c.claims[i].src == claimOther {
				seen[c.claims[i].name] = struct{}{}
			}
		}
	}
	add(p.app)
	for i := range p.rules {
		add(p.rules[i].allow)
	}
	out := slices.Collect(maps.Keys(seen))
	sort.Strings(out)
	return out
}

// builtinClaim says the name reads the verified identity, not
// Identity.Claims.
func builtinClaim(name string) bool {
	switch name {
	case "sub", "idp", "email", "name", "groups":
		return true
	}
	return false
}

func validClaimName(name string) bool {
	if name == "" || len(name) > maxClaimNameBytes {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x21 || name[i] >= 0x7f {
			return false
		}
	}
	return true
}

// CleanClaims prepares a sign-in's claims for Identity.Claims: names
// that read the verified identity (sub, idp, email, name, groups) and
// empty values are dropped, repeated values are kept once, and a claim
// left with no values is dropped. It returns nil when nothing is left.
// It fails when the claims break the session limits, a name is not 1 to
// 256 bytes of visible ASCII, or a value is longer than
// MaxClaimValueBytes or not valid UTF-8 (which a session could not store
// and read back unchanged).
func CleanClaims(in map[string][]string) (map[string][]string, error) {
	var out map[string][]string
	total := 0
	names := slices.Sorted(maps.Keys(in))
	for _, name := range names {
		if builtinClaim(name) {
			continue
		}
		if !validClaimName(name) {
			return nil, fmt.Errorf("claim name %q is not 1 to %d bytes of visible ASCII", trunc(name), maxClaimNameBytes)
		}
		var vals []string
		for _, v := range in[name] {
			if v == "" || slices.Contains(vals, v) {
				continue
			}
			if len(v) > MaxClaimValueBytes || !utf8.ValidString(v) {
				return nil, fmt.Errorf("claim %q has a value that is longer than %d bytes or not valid UTF-8", name, MaxClaimValueBytes)
			}
			if len(vals) == MaxSessionClaimValues {
				return nil, fmt.Errorf("claim %q has more than %d values", name, MaxSessionClaimValues)
			}
			vals = append(vals, v)
			total += len(v)
		}
		if len(vals) == 0 {
			continue
		}
		if out == nil {
			out = map[string][]string{}
		}
		if len(out) == MaxSessionClaims {
			return nil, fmt.Errorf("more than %d claims", MaxSessionClaims)
		}
		out[name] = vals
		total += len(name)
		if total > MaxSessionClaimBytes {
			return nil, fmt.Errorf("claims are larger than %d bytes together", MaxSessionClaimBytes)
		}
	}
	return out, nil
}

// CheckClaims checks claims that should already be clean, such as those
// of a session read back or a synthetic identity: it fails where
// CleanClaims would change them.
func CheckClaims(c map[string][]string) error {
	if len(c) == 0 {
		return nil
	}
	clean, err := CleanClaims(c)
	if err != nil {
		return err
	}
	if len(clean) != len(c) {
		return errors.New("claims must not name sub, idp, email, name or groups, or have a claim without values")
	}
	for name, vals := range c {
		if !slices.Equal(vals, clean[name]) {
			return fmt.Errorf("claim %q has an empty or repeated value", name)
		}
	}
	return nil
}

// SelectClaims returns the claims of in that names lists, as CleanClaims
// prepares them.
func SelectClaims(in map[string][]string, names []string) (map[string][]string, error) {
	if len(names) == 0 || len(in) == 0 {
		return nil, nil
	}
	pick := make(map[string][]string, len(names))
	for _, n := range names {
		if v, ok := in[n]; ok {
			pick[n] = v
		}
	}
	return CleanClaims(pick)
}

// Clone returns a copy of id that shares no slice or map with it.
func (id Identity) Clone() Identity {
	id.Groups = slices.Clone(id.Groups)
	if id.Claims != nil {
		c := make(map[string][]string, len(id.Claims))
		for k, v := range id.Claims {
			c[k] = slices.Clone(v)
		}
		id.Claims = c
	}
	return id
}

func trunc(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}
