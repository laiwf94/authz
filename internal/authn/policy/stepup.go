package policy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// StepUp makes a path rule ask for a recent sign-in, a stronger one, or
// both. A signed-in user who passes the rule but whose sign-in does not
// satisfy it is sent back to the identity provider (with OpenID Connect
// max_age and acr_values, or a SAML ForceAuthn and RequestedAuthnContext),
// and the provider's answer is checked against the same requirement
// before the new session is made.
type StepUp struct {
	// MaxAge is how long ago the user may have authenticated at the
	// provider, at least MinStepUpMaxAge; zero means any time.
	MaxAge time.Duration
	// ACRValues are the authentication context classes (OpenID Connect
	// acr, SAML AuthnContextClassRef) that satisfy the rule, compared
	// exactly; empty means any.
	ACRValues []string
}

// Limits on a StepUp.
const (
	// MinStepUpMaxAge is the shortest max_age a rule may ask for. Every
	// request to a step-up path is checked again, so a shorter one would
	// send a user back to the provider while they are still working.
	MinStepUpMaxAge = time.Minute
	// MaxStepUpMaxAge is the longest.
	MaxStepUpMaxAge = 30 * 24 * time.Hour
	// StepUpLoopWindow is how long after a step-up login a failure of the
	// rule that asked for it is taken for a loop (see IsStepUpLoop).
	StepUpLoopWindow = time.Minute
	// MaxACRValues bounds the classes one rule may list, and MaxACRBytes
	// the length of each.
	MaxACRValues = 8
	MaxACRBytes  = 256
)

// Reason codes for a sign-in that does not satisfy a rule's StepUp.
const (
	StepUpMaxAge = "step_up_max_age"
	StepUpACR    = "step_up_acr"
	// StepUpLoop is a step-up login whose session at once failed the rule
	// that asked for it: the user is shown a page instead of being sent
	// round again.
	StepUpLoop = "step_up_loop"
)

// Auth is when and how a session's user authenticated at the identity
// provider: auth_time and acr, or AuthnInstant and AuthnContextClassRef.
// A zero Time is unknown and satisfies no max_age.
type Auth struct {
	Time time.Time
	ACR  string
}

// IsStepUp says whether reason is one of the step-up reason codes, for
// which the user should sign in again rather than be refused.
func IsStepUp(reason string) bool { return reason == StepUpMaxAge || reason == StepUpACR }

// Satisfied says whether a sign-in meets the requirement at now, and if
// not, which part it fails. A Time after now counts as now, so a provider
// whose clock runs ahead does not make a sign-in look older. It does not
// allocate.
func (s *StepUp) Satisfied(a Auth, now time.Time) (bool, string) {
	if s == nil {
		return true, ""
	}
	if s.MaxAge > 0 && (a.Time.IsZero() || now.Sub(a.Time) > s.MaxAge) {
		return false, StepUpMaxAge
	}
	if len(s.ACRValues) > 0 {
		for _, v := range s.ACRValues {
			if v == a.ACR {
				return true, ""
			}
		}
		return false, StepUpACR
	}
	return true, ""
}

// IsStepUpLoop says whether sending a user to sign in again cannot help:
// their session was made by a step-up login for this same rule less than
// StepUpLoopWindow ago, and its sign-in did not satisfy the rule even when
// the session was made. The callback checks the provider's answer before
// making the session, so that happens only when the provider answered
// something else than the gateway found, or the rule changed under the
// login. A sign-in that was fresh then and has since grown too old is not
// a loop. After the window the user may step up again, so a rule made
// stricter by a reload does not lock out its sessions.
func (s *StepUp) IsStepUpLoop(a Auth, created, now time.Time) bool {
	if now.Sub(created) >= StepUpLoopWindow {
		return false
	}
	ok, _ := s.Satisfied(a, created)
	return !ok
}

// MaxAgeSeconds is MaxAge in whole seconds as OpenID Connect sends it,
// rounded down, or -1 when the rule sets none.
func (s *StepUp) MaxAgeSeconds() int64 {
	if s == nil || s.MaxAge <= 0 {
		return -1
	}
	return int64(s.MaxAge / time.Second)
}

// Challenge is the requirement as WWW-Authenticate parameters of an
// insufficient_user_authentication challenge (RFC 9470 section 3):
// max_age="900", acr_values="a b".
func (s *StepUp) Challenge() string {
	var parts []string
	if n := s.MaxAgeSeconds(); n >= 0 {
		parts = append(parts, `max_age="`+strconv.FormatInt(n, 10)+`"`)
	}
	if len(s.ACRValues) > 0 {
		parts = append(parts, `acr_values="`+strings.Join(s.ACRValues, " ")+`"`)
	}
	return strings.Join(parts, ", ")
}

// compileStepUp checks a rule's StepUp and returns a copy the caller
// cannot change.
func compileStepUp(s *StepUp) (*StepUp, error) {
	if s.MaxAge == 0 && len(s.ACRValues) == 0 {
		return nil, errors.New("step_up needs max_age, acr_values or both")
	}
	if s.MaxAge != 0 && (s.MaxAge < MinStepUpMaxAge || s.MaxAge > MaxStepUpMaxAge) {
		return nil, fmt.Errorf("step_up max_age %s must be between %s and %s", s.MaxAge, MinStepUpMaxAge, MaxStepUpMaxAge)
	}
	if s.MaxAge%time.Second != 0 {
		return nil, fmt.Errorf("step_up max_age %s must be whole seconds", s.MaxAge)
	}
	if len(s.ACRValues) > MaxACRValues {
		return nil, fmt.Errorf("step_up lists more than %d acr_values", MaxACRValues)
	}
	seen := map[string]bool{}
	for _, v := range s.ACRValues {
		if !ValidACR(v) {
			return nil, fmt.Errorf("step_up acr value %q must be 1-%d visible ASCII characters without '\"' or '\\'", v, MaxACRBytes)
		}
		if seen[v] {
			return nil, fmt.Errorf("step_up acr value %q is listed twice", v)
		}
		seen[v] = true
	}
	return &StepUp{MaxAge: s.MaxAge, ACRValues: append([]string(nil), s.ACRValues...)}, nil
}

// ValidACR says whether v can be an authentication context class: 1 to
// MaxACRBytes visible ASCII characters, none of them '"' or '\', so it
// fits a space-separated acr_values and a quoted challenge parameter.
func ValidACR(v string) bool {
	if v == "" || len(v) > MaxACRBytes {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// StepUp returns the step-up requirement of the rule a request matched, or
// nil when it has none.
func (p *Policy) StepUp(m *Match) *StepUp {
	if m.Rule < 0 || m.Rule >= len(p.rules) {
		return nil
	}
	return p.rules[m.Rule].stepUp
}

// StepUpRule returns the step-up requirement of the rule named name
// ("paths[3]"), or nil when there is no such rule or it has none.
func (p *Policy) StepUpRule(name string) *StepUp {
	for i := range p.rules {
		if p.rules[i].name == name {
			return p.rules[i].stepUp
		}
	}
	return nil
}
