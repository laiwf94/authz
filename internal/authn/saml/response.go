package saml

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/laiwf94/authz/internal/authn/oidc"
	"github.com/laiwf94/authz/internal/authn/policy"
)

// Error is a rejected SAML response. Reason is a stable code for audit logs.
type Error struct {
	Reason string
	Err    error
}

func (e *Error) Error() string { return "saml: " + e.Reason + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(reason string, format string, args ...any) error {
	return &Error{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// Reason codes.
const (
	ReasonMalformed     = "malformed_response"
	ReasonStatus        = "idp_status_not_success"
	ReasonUnsigned      = "signature_missing"
	ReasonSignature     = "signature_invalid"
	ReasonWrapping      = "signature_wrapping"
	ReasonDestination   = "wrong_destination"
	ReasonInResponseTo  = "wrong_in_response_to"
	ReasonIssuer        = "wrong_issuer"
	ReasonAudience      = "wrong_audience"
	ReasonRecipient     = "wrong_recipient"
	ReasonExpired       = "assertion_expired"
	ReasonNotYetValid   = "assertion_not_yet_valid"
	ReasonReplay        = "assertion_replayed"
	ReasonSubject       = "no_valid_subject"
	ReasonEncrypted     = "encrypted_assertion_rejected"
	ReasonAttributes    = "attributes_invalid"
	ReasonUnsolicited   = "unsolicited_response"
	maxEncodedResponse  = MaxXMLBytes * 4 / 3
	maxNameIDLength     = 512
	maxAttributeLength  = 512
	maxAttributeValues  = oidc.MaxGroups
	maxAssertionLife    = 24 * time.Hour
	defaultAssertionTTL = 5 * time.Minute
)

// Result is an accepted assertion.
type Result struct {
	Identity policy.Identity
	// SessionNotOnOrAfter is the IdP's cap on the session, if it set one.
	SessionNotOnOrAfter time.Time
	// SessionIndex is the IdP's handle for its session, if it gave one; a
	// LogoutRequest names it to end this session alone.
	SessionIndex string
	// AuthnInstant is when the IdP authenticated the user, and
	// AuthnContextClassRef how; zero and "" when the AuthnStatement does
	// not say.
	AuthnInstant         time.Time
	AuthnContextClassRef string
}

// ParseResponse validates a base64 SAMLResponse from the HTTP-POST binding
// that answers the AuthnRequest with ID requestID. Only SP-initiated logins
// are accepted: an empty requestID is rejected.
//
// The order matters. Structure is checked on the raw document, then the
// signature(s) are verified, and from then on only the verified element
// trees are read.
func (sp *SP) ParseResponse(encoded, requestID string) (*Result, error) {
	if requestID == "" {
		return nil, fail(ReasonUnsolicited, "IdP-initiated responses are not accepted")
	}
	if len(encoded) > maxEncodedResponse {
		return nil, fail(ReasonMalformed, "SAMLResponse larger than %d bytes", maxEncodedResponse)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
	if err != nil {
		return nil, fail(ReasonMalformed, "SAMLResponse is not base64")
	}
	doc, err := parseStrict(raw)
	if err != nil {
		return nil, fail(ReasonMalformed, "%v", err)
	}
	resp := doc.Root()
	if !is(resp, NSProtocol, "Response") || attr(resp, "Version") != "2.0" {
		return nil, fail(ReasonMalformed, "root is not a SAML 2.0 samlp:Response")
	}
	now := sp.cfg.Now()

	// One assertion per response, counted anywhere in the document, so an
	// extra assertion hidden in Extensions, ds:Object or Advice can't be
	// the one that gets read.
	if n := descendants(resp, NSAssertion, "Assertion") + descendants(resp, NSAssertion, "EncryptedAssertion"); n != 1 {
		return nil, fail(ReasonWrapping, "response contains %d assertions, want exactly 1", n)
	}

	responseSigned := false
	if verified, err := verifySigned(resp, resp, sp.cfg.IdP.Certs, now); err == nil {
		resp, responseSigned = verified, true
	} else if !errors.Is(err, errNoSignature) {
		return nil, signatureFailure(err)
	}

	if err := sp.checkResponse(resp, requestID, responseSigned); err != nil {
		return nil, err
	}

	assertion, scope, err := sp.assertion(resp, responseSigned)
	if err != nil {
		return nil, err
	}
	assertionSigned := false
	if verified, err := verifySigned(scope, assertion, sp.cfg.IdP.Certs, now); err == nil {
		assertion, assertionSigned = verified, true
	} else if !errors.Is(err, errNoSignature) {
		return nil, signatureFailure(err)
	}
	if !responseSigned && !assertionSigned {
		return nil, fail(ReasonUnsigned, "neither the response nor the assertion is signed")
	}
	return sp.checkAssertion(assertion, requestID, now)
}

func signatureFailure(err error) error {
	var we *wrappingError
	if errors.As(err, &we) {
		return &Error{Reason: ReasonWrapping, Err: err}
	}
	return &Error{Reason: ReasonSignature, Err: err}
}

// checkResponse validates the protocol envelope: Status, Destination and
// InResponseTo.
func (sp *SP) checkResponse(resp *etree.Element, requestID string, signed bool) error {
	if !idRe.MatchString(attr(resp, "ID")) {
		return fail(ReasonMalformed, "response has no valid ID")
	}
	status, err := child(resp, NSProtocol, "Status")
	if err != nil || status == nil {
		return fail(ReasonMalformed, "response needs exactly one Status")
	}
	code, err := child(status, NSProtocol, "StatusCode")
	if err != nil || code == nil {
		return fail(ReasonMalformed, "Status needs exactly one StatusCode")
	}
	if v := attr(code, "Value"); v != StatusSuccess {
		return fail(ReasonStatus, "IdP returned status %q", truncate(v, 128))
	}
	// Profiles 4.1.4.5: a signed response must carry Destination, and when
	// present it must be our ACS URL.
	dest := attr(resp, "Destination")
	if dest != sp.cfg.ACSURL && (dest != "" || signed) {
		return fail(ReasonDestination, "Destination %q is not this ACS", truncate(dest, 256))
	}
	if irt := attr(resp, "InResponseTo"); irt != "" && irt != requestID {
		return fail(ReasonInResponseTo, "response InResponseTo does not match the request")
	}
	if iss, _ := child(resp, NSAssertion, "Issuer"); iss != nil {
		if t, err := text(iss); err != nil || t != sp.cfg.IdP.EntityID {
			return fail(ReasonIssuer, "response Issuer is not the configured IdP")
		}
	}
	return nil
}

// assertion returns the response's single assertion, decrypting it if
// needed, and the document scope its ID must be unique in.
func (sp *SP) assertion(resp *etree.Element, responseSigned bool) (a, scope *etree.Element, err error) {
	plain := children(resp, NSAssertion, "Assertion")
	enc := children(resp, NSAssertion, "EncryptedAssertion")
	if len(plain)+len(enc) != 1 {
		return nil, nil, fail(ReasonWrapping, "assertion is not a direct child of the response")
	}
	if len(plain) == 1 {
		return plain[0], resp, nil
	}
	pt, err := decryptAssertion(enc[0], sp.cfg.Key, responseSigned)
	if err != nil {
		return nil, nil, &Error{Reason: ReasonEncrypted, Err: err}
	}
	doc, err := parseStrict(pt)
	if err != nil {
		return nil, nil, fail(ReasonEncrypted, "decrypted assertion: %v", err)
	}
	a = doc.Root()
	if !is(a, NSAssertion, "Assertion") || descendants(a, NSAssertion, "Assertion") != 1 ||
		descendants(a, NSAssertion, "EncryptedAssertion") != 0 {
		return nil, nil, fail(ReasonWrapping, "decrypted content is not exactly one Assertion")
	}
	return a, a, nil
}

func (sp *SP) checkAssertion(a *etree.Element, requestID string, now time.Time) (*Result, error) {
	skew := sp.cfg.Skew
	if attr(a, "Version") != "2.0" || !idRe.MatchString(attr(a, "ID")) {
		return nil, fail(ReasonMalformed, "assertion has no valid ID or version")
	}
	iss, err := child(a, NSAssertion, "Issuer")
	if err != nil || iss == nil {
		return nil, fail(ReasonIssuer, "assertion needs exactly one Issuer")
	}
	if t, err := text(iss); err != nil || t != sp.cfg.IdP.EntityID {
		return nil, fail(ReasonIssuer, "assertion Issuer is not the configured IdP")
	}

	// Conditions: time window and audience (Core section 2.5).
	cond, err := child(a, NSAssertion, "Conditions")
	if err != nil || cond == nil {
		return nil, fail(ReasonMalformed, "assertion needs exactly one Conditions")
	}
	notBefore, err := optionalTime(cond, "NotBefore")
	if err != nil {
		return nil, err
	}
	notOnOrAfter, err := optionalTime(cond, "NotOnOrAfter")
	if err != nil {
		return nil, err
	}
	if !notBefore.IsZero() && now.Add(skew).Before(notBefore) {
		return nil, fail(ReasonNotYetValid, "assertion not valid before %s", notBefore.Format(time.RFC3339))
	}
	if !notOnOrAfter.IsZero() && !now.Before(notOnOrAfter.Add(skew)) {
		return nil, fail(ReasonExpired, "assertion expired at %s", notOnOrAfter.Format(time.RFC3339))
	}
	ars := children(cond, NSAssertion, "AudienceRestriction")
	if len(ars) == 0 {
		return nil, fail(ReasonAudience, "assertion has no AudienceRestriction")
	}
	// Every AudienceRestriction must include us (Core section 2.5.1.4).
	for _, ar := range ars {
		ok := false
		for _, au := range children(ar, NSAssertion, "Audience") {
			if t, err := text(au); err == nil && t == sp.cfg.EntityID {
				ok = true
			}
		}
		if !ok {
			return nil, fail(ReasonAudience, "assertion is not addressed to this SP")
		}
	}

	nameID, confirmExpiry, err := sp.subject(a, requestID, now)
	if err != nil {
		return nil, err
	}

	authn := children(a, NSAssertion, "AuthnStatement")
	if len(authn) != 1 {
		return nil, fail(ReasonMalformed, "assertion needs exactly one AuthnStatement")
	}
	sessionEnd, err := optionalTime(authn[0], "SessionNotOnOrAfter")
	if err != nil {
		return nil, err
	}
	// The session index is kept to match a later LogoutRequest, so one that
	// could not be matched exactly is refused rather than dropped.
	sessionIndex := attr(authn[0], "SessionIndex")
	if sessionIndex != "" && !ValidSessionIndex(sessionIndex) {
		return nil, fail(ReasonMalformed, "SessionIndex must be 1-%d visible ASCII characters", MaxSessionIndexBytes)
	}

	authnInstant, err := optionalTime(authn[0], "AuthnInstant")
	if err != nil {
		return nil, err
	}
	classRef := ""
	if ctx := children(authn[0], NSAssertion, "AuthnContext"); len(ctx) == 1 {
		if refs := children(ctx[0], NSAssertion, "AuthnContextClassRef"); len(refs) == 1 {
			classRef = strings.TrimSpace(refs[0].Text())
			if !policy.ValidACR(classRef) {
				return nil, fail(ReasonMalformed, "AuthnContextClassRef must be 1-%d visible ASCII characters", policy.MaxACRBytes)
			}
		}
	}

	// The ID is remembered until the assertion can no longer be accepted.
	expires := confirmExpiry
	if !notOnOrAfter.IsZero() && notOnOrAfter.Before(expires) {
		expires = notOnOrAfter
	}
	if !sp.cfg.Replay.Claim(sp.cfg.ProviderID+"\x00"+attr(a, "ID"), expires.Add(skew)) {
		return nil, fail(ReasonReplay, "assertion ID already used (or the replay cache is full)")
	}

	id := policy.Identity{Provider: sp.cfg.ProviderID, Subject: nameID}
	attrs, err := attributes(a)
	if err != nil {
		return nil, err
	}
	if sp.cfg.EmailAttr != "" {
		id.Email = oidc.NormalizeEmail(first(attrs[sp.cfg.EmailAttr]))
	}
	if sp.cfg.NameAttr != "" {
		id.Name = first(attrs[sp.cfg.NameAttr])
	}
	if sp.cfg.GroupsAttr != "" {
		if id.Groups, err = oidc.CleanGroups(attrs[sp.cfg.GroupsAttr]); err != nil {
			return nil, fail(ReasonAttributes, "%v", err)
		}
	}
	return &Result{Identity: id, SessionNotOnOrAfter: sessionEnd, SessionIndex: sessionIndex,
		AuthnInstant: authnInstant, AuthnContextClassRef: classRef}, nil
}

// subject finds a bearer SubjectConfirmation that answers our request at our
// ACS and has not expired (Profiles section 4.1.4.2-4.1.4.3). It returns the
// NameID and the confirmation's expiry.
func (sp *SP) subject(a *etree.Element, requestID string, now time.Time) (string, time.Time, error) {
	subj, err := child(a, NSAssertion, "Subject")
	if err != nil || subj == nil {
		return "", time.Time{}, fail(ReasonSubject, "assertion needs exactly one Subject")
	}
	nid, err := child(subj, NSAssertion, "NameID")
	if err != nil || nid == nil {
		return "", time.Time{}, fail(ReasonSubject, "Subject needs exactly one NameID (encrypted NameIDs are not supported)")
	}
	nameID, err := text(nid)
	if err != nil || nameID == "" || len(nameID) > maxNameIDLength || truncate(nameID, maxNameIDLength) != nameID {
		return "", time.Time{}, fail(ReasonSubject, "NameID must be 1-%d bytes of plain text", maxNameIDLength)
	}
	var lastErr error = fail(ReasonSubject, "no bearer SubjectConfirmation")
	for _, sc := range children(subj, NSAssertion, "SubjectConfirmation") {
		if attr(sc, "Method") != MethodBearer {
			continue
		}
		scd, err := child(sc, NSAssertion, "SubjectConfirmationData")
		if err != nil || scd == nil {
			lastErr = fail(ReasonSubject, "bearer confirmation without SubjectConfirmationData")
			continue
		}
		if attr(scd, "Recipient") != sp.cfg.ACSURL {
			lastErr = fail(ReasonRecipient, "Recipient is not this ACS")
			continue
		}
		if attr(scd, "InResponseTo") != requestID {
			lastErr = fail(ReasonInResponseTo, "SubjectConfirmationData InResponseTo does not match the request")
			continue
		}
		if attr(scd, "NotBefore") != "" {
			lastErr = fail(ReasonSubject, "bearer confirmation must not have NotBefore")
			continue
		}
		exp, err := optionalTime(scd, "NotOnOrAfter")
		if err != nil {
			return "", time.Time{}, err
		}
		if exp.IsZero() {
			lastErr = fail(ReasonSubject, "bearer confirmation needs NotOnOrAfter")
			continue
		}
		if !now.Before(exp.Add(sp.cfg.Skew)) {
			lastErr = fail(ReasonExpired, "bearer confirmation expired at %s", exp.Format(time.RFC3339))
			continue
		}
		if exp.Sub(now) > maxAssertionLife {
			lastErr = fail(ReasonSubject, "bearer confirmation valid for longer than %s", maxAssertionLife)
			continue
		}
		return nameID, exp, nil
	}
	return "", time.Time{}, lastErr
}

// attributes collects AttributeStatement values by Name. Every value must be
// plain text.
func attributes(a *etree.Element) (map[string][]string, error) {
	out := map[string][]string{}
	for _, st := range children(a, NSAssertion, "AttributeStatement") {
		for _, at := range children(st, NSAssertion, "Attribute") {
			name := attr(at, "Name")
			for _, v := range children(at, NSAssertion, "AttributeValue") {
				t, err := text(v)
				if err != nil || len(t) > maxAttributeLength {
					return nil, fail(ReasonAttributes, "attribute %q has a value that is not short plain text", truncate(name, 64))
				}
				if len(out[name]) >= maxAttributeValues {
					return nil, fail(ReasonAttributes, "attribute %q has more than %d values", truncate(name, 64), maxAttributeValues)
				}
				out[name] = append(out[name], t)
			}
		}
	}
	return out, nil
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func optionalTime(el *etree.Element, name string) (time.Time, error) {
	v := attr(el, name)
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, fail(ReasonMalformed, "%s is not an xs:dateTime", name)
	}
	return t, nil
}

// truncate bounds s for messages and drops control characters.
func truncate(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len()+len(string(r)) > n {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
