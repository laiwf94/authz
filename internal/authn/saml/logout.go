package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Single Logout, service provider side (SAML 2.0 Profiles section 4.4).
//
// Both directions run over the front channel, through the browser, on the
// HTTP-Redirect and HTTP-POST bindings:
//
//   - SP-initiated: the user signs out here; NewLogoutRequest builds the
//     LogoutRequest for the identity provider, and ReadLogout checks the
//     LogoutResponse it sends back.
//   - IdP-initiated: the user signs out at the identity provider (or at
//     another service provider); ReadLogout checks its LogoutRequest, the
//     caller ends the sessions it names, and NewLogoutResponse answers.
//
// Every message must be signed, in either direction (Profiles section
// 4.4.3.1 and 4.4.4.1 ask the binding to authenticate the sender, and a
// front-channel binding can't without a signature): an unsigned
// LogoutRequest would let any page sign anyone out. Single logout is
// therefore enabled only with an SP key and an identity provider whose
// metadata lists a SingleLogoutService.

// Reasons a logout message is refused, beyond the ones a Response shares.
const (
	ReasonLogoutDisabled = "single_logout_disabled"
	ReasonLogoutReplay   = "logout_replayed"
)

// StatusPartialLogout is the second-level status a LogoutResponse uses when
// some session participants could not be signed out (Core section 3.7.3.2).
const (
	StatusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
	StatusRequester     = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	StatusResponder     = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	nameIDEntity        = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	logoutReasonUser    = "urn:oasis:names:tc:SAML:2.0:logout:user"
)

const (
	// maxLogoutAge is how old a logout message's IssueInstant may be (plus
	// skew). A message is used once, and its ID is remembered this long.
	maxLogoutAge = 10 * time.Minute
	// maxSessionIndexes bounds the SessionIndex elements of one request.
	maxSessionIndexes = 16
	// MaxSessionIndexBytes bounds a SessionIndex the SP keeps and accepts.
	MaxSessionIndexBytes = 255
	maxRelayState        = 80
)

// Endpoint is a SingleLogoutService of the identity provider for one
// binding.
type Endpoint struct {
	Location         string // where requests go
	ResponseLocation string // where responses go, if not Location
}

// LogoutRequest is an accepted LogoutRequest from the identity provider.
type LogoutRequest struct {
	ID     string
	NameID string
	// SessionIndexes are the identity provider's sessions to end; empty
	// means every session of NameID (Core section 3.7.3.2).
	SessionIndexes []string
	Reason         string
}

// LogoutResponse is an accepted LogoutResponse from the identity provider.
type LogoutResponse struct {
	ID           string
	InResponseTo string
	Status       string // top-level StatusCode
	SubStatus    string // second-level StatusCode, if any
}

// Success reports whether the identity provider ended every session.
func (r *LogoutResponse) Success() bool { return r.Status == StatusSuccess && r.SubStatus == "" }

// Inbound is a verified logout message that arrived at the SP's
// SingleLogoutService. Exactly one of Request and Response is set.
type Inbound struct {
	Binding    string
	RelayState string
	Request    *LogoutRequest
	Response   *LogoutResponse
}

// Message is an outbound protocol message for the browser to carry. With
// the HTTP-Redirect binding the browser is sent to URL; with HTTP-POST it
// submits Form to URL.
type Message struct {
	Binding string
	URL     string
	Form    url.Values
}

// ValidSessionIndex reports whether v can be kept and matched as an
// identity provider session handle: 1-255 visible ASCII characters.
func ValidSessionIndex(v string) bool {
	if v == "" || len(v) > MaxSessionIndexBytes {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// LogoutEnabled reports whether single logout is available: the SP has a
// SingleLogoutService URL and a signing key, and the identity provider
// lists a SingleLogoutService.
func (sp *SP) LogoutEnabled() bool {
	return sp.cfg.SLOURL != "" && sp.cfg.Key != nil && len(sp.cfg.IdP.SingleLogout) > 0
}

// logoutEndpoint picks the identity provider's endpoint for binding, or
// for the other binding if it lists only that one.
func (sp *SP) logoutEndpoint(binding string) (string, Endpoint) {
	if ep, ok := sp.cfg.IdP.SingleLogout[binding]; ok {
		return binding, ep
	}
	for _, b := range []string{BindingRedirect, BindingPOST} {
		if ep, ok := sp.cfg.IdP.SingleLogout[b]; ok {
			return b, ep
		}
	}
	return "", Endpoint{}
}

// NewLogoutRequest builds the signed LogoutRequest that ends the identity
// provider's session sessionIndex (or, if empty, every session) of nameID,
// on the HTTP-Redirect binding if the identity provider takes it and
// HTTP-POST otherwise. The answer comes back to the SP's SingleLogoutService
// with InResponseTo set to requestID and relayState echoed.
func (sp *SP) NewLogoutRequest(requestID, nameID, sessionIndex, relayState string) (*Message, error) {
	if !sp.LogoutEnabled() {
		return nil, fail(ReasonLogoutDisabled, "single logout is not configured")
	}
	if !idRe.MatchString(requestID) || nameID == "" || (sessionIndex != "" && !ValidSessionIndex(sessionIndex)) {
		return nil, fail(ReasonMalformed, "logout request needs an ID, a NameID and a valid SessionIndex")
	}
	binding, ep := sp.logoutEndpoint(BindingRedirect)
	now := sp.cfg.Now().UTC()
	doc := etree.NewDocument()
	req := doc.CreateElement("samlp:LogoutRequest")
	req.CreateAttr("xmlns:samlp", NSProtocol)
	req.CreateAttr("xmlns:saml", NSAssertion)
	req.CreateAttr("ID", requestID)
	req.CreateAttr("Version", "2.0")
	req.CreateAttr("IssueInstant", now.Format(timeFormat))
	req.CreateAttr("Destination", ep.Location)
	req.CreateAttr("NotOnOrAfter", now.Add(maxLogoutAge).Format(timeFormat))
	req.CreateAttr("Reason", logoutReasonUser)
	req.CreateElement("saml:Issuer").SetText(sp.cfg.EntityID)
	nid := req.CreateElement("saml:NameID")
	if sp.cfg.NameIDFormat != NameIDUnspecified {
		nid.CreateAttr("Format", sp.cfg.NameIDFormat)
	}
	nid.SetText(nameID)
	if sessionIndex != "" {
		req.CreateElement("samlp:SessionIndex").SetText(sessionIndex)
	}
	return sp.outbound(doc, binding, ep.Location, "SAMLRequest", relayState)
}

// NewLogoutResponse builds the signed LogoutResponse to the identity
// provider's request inResponseTo, with top-level status, on the binding the
// request came over (or the other one, if the identity provider lists only
// that). relayState must be the request's.
func (sp *SP) NewLogoutResponse(inResponseTo, status, relayState, binding string) (*Message, error) {
	if !sp.LogoutEnabled() {
		return nil, fail(ReasonLogoutDisabled, "single logout is not configured")
	}
	if !idRe.MatchString(inResponseTo) {
		return nil, fail(ReasonMalformed, "logout response needs the request ID")
	}
	binding, ep := sp.logoutEndpoint(binding)
	dest := ep.ResponseLocation
	if dest == "" {
		dest = ep.Location
	}
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:LogoutResponse")
	resp.CreateAttr("xmlns:samlp", NSProtocol)
	resp.CreateAttr("xmlns:saml", NSAssertion)
	resp.CreateAttr("ID", NewRequestID())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", sp.cfg.Now().UTC().Format(timeFormat))
	resp.CreateAttr("Destination", dest)
	resp.CreateAttr("InResponseTo", inResponseTo)
	resp.CreateElement("saml:Issuer").SetText(sp.cfg.EntityID)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", status)
	return sp.outbound(doc, binding, dest, "SAMLResponse", relayState)
}

// outbound encodes and signs doc for binding: deflated in the query with a
// query-string signature for HTTP-Redirect (Bindings section 3.4.4.1), an
// enveloped XML signature for HTTP-POST (section 3.5.4).
func (sp *SP) outbound(doc *etree.Document, binding, dest, param, relayState string) (*Message, error) {
	if len(relayState) > maxRelayState {
		return nil, errors.New("saml: RelayState longer than 80 bytes")
	}
	switch binding {
	case BindingRedirect:
		raw, err := doc.WriteToBytes()
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		fw, _ := flate.NewWriter(&buf, flate.BestCompression)
		fw.Write(raw)
		fw.Close()
		q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
		if relayState != "" {
			q += "&RelayState=" + url.QueryEscape(relayState)
		}
		if q, err = sp.signQuery(q); err != nil {
			return nil, err
		}
		sep := "?"
		if strings.Contains(dest, "?") {
			sep = "&"
		}
		return &Message{Binding: binding, URL: dest + sep + q}, nil
	case BindingPOST:
		ctx, err := dsig.NewSigningContext(sp.cfg.Key, [][]byte{sp.cfg.Cert.Raw})
		if err != nil {
			return nil, err
		}
		ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
			return nil, err
		}
		root := doc.Root()
		sig, err := ctx.ConstructSignature(root, true)
		if err != nil {
			return nil, err
		}
		// The schema puts the signature right after Issuer, the first child.
		root.InsertChildAt(1, sig)
		raw, err := doc.WriteToBytes()
		if err != nil {
			return nil, err
		}
		f := url.Values{param: {base64.StdEncoding.EncodeToString(raw)}}
		if relayState != "" {
			f.Set("RelayState", relayState)
		}
		return &Message{Binding: binding, URL: dest, Form: f}, nil
	}
	return nil, errors.New("saml: unsupported binding")
}

// signQuery appends SigAlg and Signature to an HTTP-Redirect query. The
// signed string is the query in exactly this order (Bindings section
// 3.4.4.1), so callers assemble it by hand.
func (sp *SP) signQuery(q string) (string, error) {
	q += "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
	sum := crypto.SHA256.New()
	sum.Write([]byte(q))
	sig, err := rsa.SignPKCS1v15(rand.Reader, sp.cfg.Key, crypto.SHA256, sum.Sum(nil))
	if err != nil {
		return "", err
	}
	return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig)), nil
}

// ReadLogout verifies a message that arrived at the SP's SingleLogoutService:
// a GET carries it on the HTTP-Redirect binding in rawQuery, a POST on the
// HTTP-POST binding in form (the parsed body only, never the query).
//
// It checks the signature (required on both bindings, against the identity
// provider's certificates), then from the signed content only: the version,
// ID, IssueInstant (at most ten minutes old), Destination (this
// SingleLogoutService, always required), Issuer (the identity provider), and
// for a request NotOnOrAfter, the NameID and SessionIndexes; for a response
// InResponseTo and the status. Each message ID is accepted once. Matching a
// response's InResponseTo to the request this SP sent is the caller's job.
func (sp *SP) ReadLogout(method, rawQuery string, form url.Values) (*Inbound, error) {
	if !sp.LogoutEnabled() {
		return nil, fail(ReasonLogoutDisabled, "single logout is not configured")
	}
	now := sp.cfg.Now()
	in := &Inbound{}
	var root *etree.Element
	var param string
	var err error
	switch method {
	case http.MethodGet:
		in.Binding = BindingRedirect
		root, param, in.RelayState, err = sp.readRedirect(rawQuery, now)
	case http.MethodPost:
		in.Binding = BindingPOST
		root, param, in.RelayState, err = sp.readPOST(form, now)
	default:
		err = fail(ReasonMalformed, "logout messages come by GET or POST")
	}
	if err != nil {
		return nil, err
	}
	if len(in.RelayState) > maxRelayState || truncate(in.RelayState, maxRelayState) != in.RelayState {
		return nil, fail(ReasonMalformed, "RelayState must be at most %d bytes of plain text", maxRelayState)
	}
	switch {
	case param == "SAMLRequest" && is(root, NSProtocol, "LogoutRequest"):
		in.Request, err = sp.checkLogoutRequest(root, now)
	case param == "SAMLResponse" && is(root, NSProtocol, "LogoutResponse"):
		in.Response, err = sp.checkLogoutResponse(root, now)
	default:
		err = fail(ReasonMalformed, "%s does not hold a SAML 2.0 Logout%s", param,
			strings.TrimPrefix(param, "SAML"))
	}
	if err != nil {
		return nil, err
	}
	return in, nil
}

// readRedirect decodes an HTTP-Redirect message and verifies its query
// signature over the parameters exactly as they were sent.
func (sp *SP) readRedirect(rawQuery string, now time.Time) (*etree.Element, string, string, error) {
	if len(rawQuery) > 2*maxEncodedResponse {
		return nil, "", "", fail(ReasonMalformed, "query larger than %d bytes", 2*maxEncodedResponse)
	}
	raw := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature":
			// A repeated parameter could mean one value is signed and
			// another read.
			if _, dup := raw[k]; dup {
				return nil, "", "", fail(ReasonMalformed, "%s appears more than once", k)
			}
			raw[k] = v
		}
	}
	param := "SAMLRequest"
	_, hasReq := raw["SAMLRequest"]
	_, hasResp := raw["SAMLResponse"]
	switch {
	case hasReq && hasResp, !hasReq && !hasResp:
		return nil, "", "", fail(ReasonMalformed, "need exactly one of SAMLRequest and SAMLResponse")
	case hasResp:
		param = "SAMLResponse"
	}
	rawAlg, hasAlg := raw["SigAlg"]
	rawSig, hasSig := raw["Signature"]
	if !hasAlg || !hasSig {
		return nil, "", "", fail(ReasonUnsigned, "logout messages must be signed (SigAlg and Signature)")
	}
	signed := param + "=" + raw[param]
	rawRelay, hasRelay := raw["RelayState"]
	if hasRelay {
		signed += "&RelayState=" + rawRelay
	}
	signed += "&SigAlg=" + rawAlg
	alg, err1 := url.QueryUnescape(rawAlg)
	sig, err2 := decodeQueryBase64(rawSig)
	relay, err3 := url.QueryUnescape(rawRelay)
	msg, err4 := decodeQueryBase64(raw[param])
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return nil, "", "", fail(ReasonMalformed, "query parameters are not URL-encoded base64")
	}
	if err := verifyQuerySignature([]byte(signed), alg, sig, sp.cfg.IdP.Certs, now); err != nil {
		return nil, "", "", &Error{Reason: ReasonSignature, Err: err}
	}
	if len(msg) > MaxXMLBytes {
		return nil, "", "", fail(ReasonMalformed, "%s larger than %d bytes", param, MaxXMLBytes)
	}
	xmlBytes, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(msg)), MaxXMLBytes+1))
	if err != nil {
		return nil, "", "", fail(ReasonMalformed, "%s is not DEFLATE-compressed", param)
	}
	doc, err := parseStrict(xmlBytes)
	if err != nil {
		return nil, "", "", fail(ReasonMalformed, "%v", err)
	}
	// The binding signs the query; a signature left in the XML (section
	// 3.4.4.1 says to remove it) is not what was verified.
	if descendants(doc.Root(), NSDSig, "Signature") != 0 {
		return nil, "", "", fail(ReasonMalformed, "an HTTP-Redirect message must not carry an XML signature")
	}
	return doc.Root(), param, relay, nil
}

// decodeQueryBase64 decodes a URL-encoded base64 parameter. Base64 has no
// spaces, so a '+' that an encoder left unescaped (and QueryUnescape turned
// into a space) is put back.
func decodeQueryBase64(v string) ([]byte, error) {
	s, err := url.QueryUnescape(v)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(s, " ", "+"))
}

// readPOST decodes an HTTP-POST message and verifies its enveloped
// signature, returning the signed element.
func (sp *SP) readPOST(form url.Values, now time.Time) (*etree.Element, string, string, error) {
	req, resp := form["SAMLRequest"], form["SAMLResponse"]
	if len(req)+len(resp) != 1 || len(form["RelayState"]) > 1 {
		return nil, "", "", fail(ReasonMalformed, "need exactly one SAMLRequest or SAMLResponse and at most one RelayState")
	}
	param, encoded := "SAMLRequest", ""
	if len(resp) == 1 {
		param, encoded = "SAMLResponse", resp[0]
	} else {
		encoded = req[0]
	}
	if len(encoded) > maxEncodedResponse {
		return nil, "", "", fail(ReasonMalformed, "%s larger than %d bytes", param, maxEncodedResponse)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
	if err != nil {
		return nil, "", "", fail(ReasonMalformed, "%s is not base64", param)
	}
	doc, err := parseStrict(raw)
	if err != nil {
		return nil, "", "", fail(ReasonMalformed, "%v", err)
	}
	root := doc.Root()
	verified, err := verifySigned(root, root, sp.cfg.IdP.Certs, now)
	if errors.Is(err, errNoSignature) {
		return nil, "", "", fail(ReasonUnsigned, "logout messages must be signed")
	}
	if err != nil {
		return nil, "", "", signatureFailure(err)
	}
	return verified, param, form.Get("RelayState"), nil
}

// checkLogoutCommon validates what requests and responses share
// (StatusResponseType and RequestAbstractType, Core section 3.2) and returns
// the message's ID and how long it must be remembered.
func (sp *SP) checkLogoutCommon(el *etree.Element, now time.Time) (string, time.Time, error) {
	skew := sp.cfg.Skew
	id := attr(el, "ID")
	if attr(el, "Version") != "2.0" || !idRe.MatchString(id) {
		return "", time.Time{}, fail(ReasonMalformed, "logout message has no valid ID or version")
	}
	issued, err := optionalTime(el, "IssueInstant")
	if err != nil {
		return "", time.Time{}, err
	}
	if issued.IsZero() {
		return "", time.Time{}, fail(ReasonMalformed, "logout message has no IssueInstant")
	}
	if now.Add(skew).Before(issued) {
		return "", time.Time{}, fail(ReasonNotYetValid, "logout message issued in the future")
	}
	if now.Sub(issued) > maxLogoutAge+skew {
		return "", time.Time{}, fail(ReasonExpired, "logout message issued more than %s ago", maxLogoutAge)
	}
	// Signed messages must name their recipient (Bindings 3.4.5.2, 3.5.5.2).
	if dest := attr(el, "Destination"); dest != sp.cfg.SLOURL {
		return "", time.Time{}, fail(ReasonDestination, "Destination %q is not this SingleLogoutService", truncate(dest, 256))
	}
	iss, err := child(el, NSAssertion, "Issuer")
	if err != nil || iss == nil {
		return "", time.Time{}, fail(ReasonIssuer, "logout message needs exactly one Issuer")
	}
	if f := attr(iss, "Format"); f != "" && f != nameIDEntity {
		return "", time.Time{}, fail(ReasonIssuer, "Issuer Format is not an entity")
	}
	if t, err := text(iss); err != nil || t != sp.cfg.IdP.EntityID {
		return "", time.Time{}, fail(ReasonIssuer, "logout message Issuer is not the configured IdP")
	}
	return id, issued.Add(maxLogoutAge + skew), nil
}

// claimLogout remembers a logout message ID until it can no longer pass.
func (sp *SP) claimLogout(id string, until time.Time) error {
	if !sp.cfg.Replay.Claim(sp.cfg.ProviderID+"\x00logout\x00"+id, until) {
		return fail(ReasonLogoutReplay, "logout message ID already used (or the replay cache is full)")
	}
	return nil
}

func (sp *SP) checkLogoutRequest(el *etree.Element, now time.Time) (*LogoutRequest, error) {
	id, until, err := sp.checkLogoutCommon(el, now)
	if err != nil {
		return nil, err
	}
	notOnOrAfter, err := optionalTime(el, "NotOnOrAfter")
	if err != nil {
		return nil, err
	}
	if !notOnOrAfter.IsZero() && !now.Before(notOnOrAfter.Add(sp.cfg.Skew)) {
		return nil, fail(ReasonExpired, "logout request expired at %s", notOnOrAfter.Format(time.RFC3339))
	}
	if len(children(el, NSAssertion, "EncryptedID"))+len(children(el, NSAssertion, "BaseID")) != 0 {
		return nil, fail(ReasonSubject, "only a plain NameID is supported in a logout request")
	}
	nid, err := child(el, NSAssertion, "NameID")
	if err != nil || nid == nil {
		return nil, fail(ReasonSubject, "logout request needs exactly one NameID")
	}
	nameID, err := text(nid)
	if err != nil || nameID == "" || len(nameID) > maxNameIDLength || truncate(nameID, maxNameIDLength) != nameID {
		return nil, fail(ReasonSubject, "NameID must be 1-%d bytes of plain text", maxNameIDLength)
	}
	req := &LogoutRequest{ID: id, NameID: nameID, Reason: truncate(attr(el, "Reason"), 128)}
	idx := children(el, NSProtocol, "SessionIndex")
	if len(idx) > maxSessionIndexes {
		return nil, fail(ReasonMalformed, "more than %d SessionIndex elements", maxSessionIndexes)
	}
	for _, x := range idx {
		v, err := text(x)
		if err != nil || !ValidSessionIndex(v) {
			return nil, fail(ReasonMalformed, "SessionIndex must be 1-%d visible ASCII characters", MaxSessionIndexBytes)
		}
		req.SessionIndexes = append(req.SessionIndexes, v)
	}
	if err := sp.claimLogout(id, until); err != nil {
		return nil, err
	}
	return req, nil
}

func (sp *SP) checkLogoutResponse(el *etree.Element, now time.Time) (*LogoutResponse, error) {
	id, until, err := sp.checkLogoutCommon(el, now)
	if err != nil {
		return nil, err
	}
	irt := attr(el, "InResponseTo")
	if !idRe.MatchString(irt) {
		// Only answers to this SP's own requests are expected.
		return nil, fail(ReasonInResponseTo, "logout response has no InResponseTo")
	}
	status, err := child(el, NSProtocol, "Status")
	if err != nil || status == nil {
		return nil, fail(ReasonMalformed, "logout response needs exactly one Status")
	}
	code, err := child(status, NSProtocol, "StatusCode")
	if err != nil || code == nil || attr(code, "Value") == "" {
		return nil, fail(ReasonMalformed, "Status needs exactly one StatusCode")
	}
	resp := &LogoutResponse{ID: id, InResponseTo: irt, Status: truncate(attr(code, "Value"), 128)}
	if sub, err := child(code, NSProtocol, "StatusCode"); err != nil {
		return nil, fail(ReasonMalformed, "StatusCode has more than one StatusCode")
	} else if sub != nil {
		resp.SubStatus = truncate(attr(sub, "Value"), 128)
	}
	if err := sp.claimLogout(id, until); err != nil {
		return nil, err
	}
	return resp, nil
}

// Query-string signature algorithms (the XML Signature URIs, as SigAlg
// carries them). SHA-1 is refused, as in XML signatures.
var querySigHashes = map[string]crypto.Hash{
	dsig.RSASHA256SignatureMethod:   crypto.SHA256,
	dsig.RSASHA384SignatureMethod:   crypto.SHA384,
	dsig.RSASHA512SignatureMethod:   crypto.SHA512,
	dsig.ECDSASHA256SignatureMethod: crypto.SHA256,
	dsig.ECDSASHA384SignatureMethod: crypto.SHA384,
	dsig.ECDSASHA512SignatureMethod: crypto.SHA512,
}

// verifyQuerySignature checks an HTTP-Redirect signature against any of the
// certificates valid at now. The algorithm must match the key type: an RSA
// SigAlg is checked only against RSA keys and an ECDSA one only against
// ECDSA keys, whose signature is r and s concatenated (XML Signature 1.1
// section 6.4.3).
func verifyQuerySignature(signed []byte, alg string, sig []byte, certs []*x509.Certificate, now time.Time) error {
	h, ok := querySigHashes[alg]
	if !ok {
		return fmt.Errorf("signature algorithm %q not allowed", truncate(alg, 128))
	}
	d := h.New()
	d.Write(signed)
	sum := d.Sum(nil)
	isECDSA := strings.Contains(alg, "ecdsa")
	for _, c := range certs {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			continue
		}
		switch pub := c.PublicKey.(type) {
		case *rsa.PublicKey:
			if !isECDSA && rsa.VerifyPKCS1v15(pub, h, sum, sig) == nil {
				return nil
			}
		case *ecdsa.PublicKey:
			n := (pub.Curve.Params().BitSize + 7) / 8
			if isECDSA && len(sig) == 2*n {
				r, s := new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])
				if ecdsa.Verify(pub, sum, r, s) {
					return nil
				}
			}
		}
	}
	return errors.New("query signature does not verify with any current IdP certificate")
}
