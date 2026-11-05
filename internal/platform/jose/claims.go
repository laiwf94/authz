package jose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// ClaimError is a claim check that failed. Reason is a stable code for audit
// logs and metrics; the message is for operators.
type ClaimError struct {
	Reason string
	Msg    string
}

func (e *ClaimError) Error() string { return "jose: " + e.Msg }

// Stable reason codes for claim failures.
const (
	ReasonIssuer    = "wrong_issuer"
	ReasonAudience  = "wrong_audience"
	ReasonExpired   = "expired"
	ReasonNotYet    = "not_yet_valid"
	ReasonIssuedAt  = "bad_issued_at"
	ReasonMissing   = "missing_claim"
	ReasonAZP       = "wrong_authorized_party"
	ReasonMalformed = "malformed_claims"
)

func claimErr(reason, format string, args ...any) error {
	return &ClaimError{Reason: reason, Msg: fmt.Sprintf(format, args...)}
}

// Audience is the "aud" claim: a single string or an array of strings.
type Audience []string

// UnmarshalJSON accepts both forms allowed by RFC 7519 section 4.1.3.
func (a *Audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = Audience{s}
		return nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return errors.New("aud must be a string or an array of strings")
	}
	*a = list
	return nil
}

// MarshalJSON writes a single audience as a string.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// NumericDate is seconds since the Unix epoch (RFC 7519 section 2).
type NumericDate int64

// maxNumericDate is the end of year 9999; larger values are rejected so time
// arithmetic can't overflow.
const maxNumericDate = 253402300799

// UnmarshalJSON accepts a JSON number, including fractional seconds, and
// rejects strings, negatives and absurd values.
func (d *NumericDate) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return errors.New("date claims must be numbers")
	}
	if math.IsNaN(f) || f < 0 || f > maxNumericDate {
		return errors.New("date claim out of range")
	}
	*d = NumericDate(int64(f))
	return nil
}

// Time converts to time.Time.
func (d NumericDate) Time() time.Time { return time.Unix(int64(d), 0) }

// Claims are the registered and OpenID Connect claims this service reads.
// All claims, including these, are also kept in Raw.
type Claims struct {
	Issuer          string       `json:"iss"`
	Subject         string       `json:"sub"`
	Audience        Audience     `json:"aud"`
	Expiry          *NumericDate `json:"exp"`
	NotBefore       *NumericDate `json:"nbf"`
	IssuedAt        *NumericDate `json:"iat"`
	Nonce           string       `json:"nonce"`
	AuthorizedParty string       `json:"azp"`
	AccessTokenHash string       `json:"at_hash"`
	Raw             map[string]json.RawMessage
}

// ParseClaims decodes a JWT payload.
func ParseClaims(payload []byte) (*Claims, error) {
	c := &Claims{}
	if err := strictUnmarshal(payload, c, false); err != nil {
		return nil, claimErr(ReasonMalformed, "claims: %v", err)
	}
	if err := strictUnmarshal(payload, &c.Raw, false); err != nil {
		return nil, claimErr(ReasonMalformed, "claims: %v", err)
	}
	return c, nil
}

// String returns a string claim from Raw, or "" if absent or not a string.
func (c *Claims) String(name string) string {
	var s string
	if raw, ok := c.Raw[name]; ok {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}

// Bool returns a boolean claim and whether it was present as a boolean.
func (c *Claims) Bool(name string) (value, ok bool) {
	raw, present := c.Raw[name]
	if !present {
		return false, false
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, false
	}
	return value, true
}

// Strings returns a claim that is a string or an array of strings. Other
// shapes return an error, so a malformed groups claim is not silently empty.
func (c *Claims) Strings(name string) ([]string, error) {
	raw, ok := c.Raw[name]
	if !ok || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var a Audience
	if err := a.UnmarshalJSON(raw); err != nil {
		return nil, claimErr(ReasonMalformed, "claim %q must be a string or an array of strings", name)
	}
	return a, nil
}

// Expect lists what Validate checks.
type Expect struct {
	Issuer   string
	Audience string
	Now      time.Time
	Skew     time.Duration
	// MaxAge rejects tokens issued longer ago than this (0 = no bound).
	MaxAge time.Duration
	// TrustedAudiences may appear next to Audience. Any other extra audience
	// is rejected (OpenID Connect Core section 3.1.3.7, step 3).
	TrustedAudiences []string
}

// Validate checks iss, aud, azp, exp, nbf and iat. exp and iat are required.
func (c *Claims) Validate(e Expect) error {
	if c.Issuer != e.Issuer {
		return claimErr(ReasonIssuer, "issuer %q, want %q", c.Issuer, e.Issuer)
	}
	if !contains(c.Audience, e.Audience) {
		return claimErr(ReasonAudience, "audience %q does not include %q", []string(c.Audience), e.Audience)
	}
	for _, a := range c.Audience {
		if a != e.Audience && !contains(e.TrustedAudiences, a) {
			return claimErr(ReasonAudience, "untrusted additional audience %q", a)
		}
	}
	// Core 3.1.3.7 steps 4-5: with several audiences azp should be present,
	// and when present it must be this client.
	if len(c.Audience) > 1 && c.AuthorizedParty == "" {
		return claimErr(ReasonAZP, "several audiences and no azp")
	}
	if c.AuthorizedParty != "" && c.AuthorizedParty != e.Audience {
		return claimErr(ReasonAZP, "azp %q, want %q", c.AuthorizedParty, e.Audience)
	}
	if c.Expiry == nil {
		return claimErr(ReasonMissing, "no exp")
	}
	if !e.Now.Before(c.Expiry.Time().Add(e.Skew)) {
		return claimErr(ReasonExpired, "expired at %d", int64(*c.Expiry))
	}
	if c.NotBefore != nil && e.Now.Add(e.Skew).Before(c.NotBefore.Time()) {
		return claimErr(ReasonNotYet, "not valid before %d", int64(*c.NotBefore))
	}
	if c.IssuedAt == nil {
		return claimErr(ReasonMissing, "no iat")
	}
	if e.Now.Add(e.Skew).Before(c.IssuedAt.Time()) {
		return claimErr(ReasonIssuedAt, "issued in the future (%d)", int64(*c.IssuedAt))
	}
	if e.MaxAge > 0 && e.Now.Sub(c.IssuedAt.Time()) > e.MaxAge+e.Skew {
		return claimErr(ReasonIssuedAt, "issued too long ago (%d)", int64(*c.IssuedAt))
	}
	return nil
}
