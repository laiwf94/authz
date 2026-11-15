package fakeidp

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAML Single Logout, identity provider side (Profiles section 4.4).
//
// With single logout enabled the metadata lists a SingleLogoutService at
// /saml/slo for the HTTP-Redirect binding, the HTTP-POST binding or both.
// The endpoint takes a service provider's LogoutRequest (it ends the SAML
// sessions it names and answers with a signed LogoutResponse on the same
// binding) and the LogoutResponse to a request the IdP sent
// (SAMLLogoutRequest builds those). Like a strict real provider, it insists
// on signed messages from a registered service provider, its LogoutCert,
// the right Destination and a known InResponseTo.

const (
	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	statusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
	statusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"
)

// Bindings for EnableSingleLogout and SAMLLogoutOptions.
const (
	Redirect = "redirect"
	POST     = "post"
)

type samlSession struct {
	email string
	sp    string // entity id
	seq   int
}

// ReceivedLogout is a LogoutRequest a service provider sent the IdP.
type ReceivedLogout struct {
	SP            string
	NameID        string
	SessionIndex  []string
	Binding       string // Redirect or POST
	EndedSessions int
}

// EnableSingleLogout lists a SingleLogoutService for these bindings
// (Redirect, POST; both when none are given) in the metadata from now on.
func (i *IdP) EnableSingleLogout(bindings ...string) {
	if len(bindings) == 0 {
		bindings = []string{Redirect, POST}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.slo = append([]string(nil), bindings...)
}

func (i *IdP) sloBindings() []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]string(nil), i.slo...)
}

// SetSAMLLogout registers a service provider's SingleLogoutService and the
// certificate its logout messages must be signed with. It reports whether
// the service provider is registered.
func (i *IdP) SetSAMLLogout(entityID, sloURL string, cert *x509.Certificate) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	sp := i.serviceProvider(entityID)
	if sp == nil {
		return false
	}
	sp.SingleLogoutURL, sp.LogoutCert = sloURL, cert
	return true
}

// addSAMLSession records the SAML session a login started and returns its
// SessionIndex.
func (i *IdP) addSAMLSession(email, sp string) string {
	idx := newID()
	i.mu.Lock()
	defer i.mu.Unlock()
	i.sloSeq++
	i.samlSessions[idx] = &samlSession{email: email, sp: sp, seq: i.sloSeq}
	return idx
}

// SAMLSessions returns the SessionIndexes of a user's live SAML sessions,
// oldest first.
func (i *IdP) SAMLSessions(email string) []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	var out []*samlSession
	idx := map[*samlSession]string{}
	for k, s := range i.samlSessions {
		if s.email == email {
			out = append(out, s)
			idx[s] = k
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].seq < out[b].seq })
	keys := make([]string, len(out))
	for n, s := range out {
		keys[n] = idx[s]
	}
	return keys
}

// LogoutRequests returns the LogoutRequests service providers sent, in
// order.
func (i *IdP) LogoutRequests() []ReceivedLogout {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]ReceivedLogout(nil), i.received...)
}

// SAMLLogoutResult returns the status of the LogoutResponse a service
// provider sent to the IdP's request id, if one arrived.
func (i *IdP) SAMLLogoutResult(id string) (string, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	st, ok := i.logoutResults[id]
	return st, ok
}

// SAMLLogoutOptions controls SAMLLogoutRequest.
type SAMLLogoutOptions struct {
	SP            string // entity id
	NameID        string
	SessionIndex  []string
	Binding       string // Redirect (default) or POST
	RelayState    string
	Unsigned      bool
	SignWithOther *rsa.PrivateKey // sign with this key instead of the IdP's
	// Mutate, when set, may change the request before it is signed.
	Mutate func(req *etree.Element)
	// EndSessions ends the IdP's own sessions the request names, as a real
	// IdP does when the user signs out there.
	EndSessions bool
}

// SAMLLogoutRequest builds an IdP-initiated LogoutRequest for the service
// provider's SingleLogoutService and returns where the browser goes: with
// Redirect a URL to GET (form is nil), with POST a URL and form to submit.
// id is the request's ID, for SAMLLogoutResult.
func (i *IdP) SAMLLogoutRequest(o SAMLLogoutOptions) (target string, form url.Values, id string, err error) {
	i.mu.Lock()
	sp := i.serviceProvider(o.SP)
	var dest string
	if sp != nil {
		dest = sp.SingleLogoutURL
	}
	if o.EndSessions {
		i.endSAMLSessions(o.SP, o.NameID, o.SessionIndex)
	}
	i.mu.Unlock()
	if sp == nil || dest == "" {
		return "", nil, "", errors.New("fakeidp: no SingleLogoutService registered for that service provider")
	}
	id = newID()
	now := i.cfg.Now().UTC()
	doc := etree.NewDocument()
	req := doc.CreateElement("samlp:LogoutRequest")
	req.CreateAttr("xmlns:samlp", nsProtocol)
	req.CreateAttr("xmlns:saml", nsAssertion)
	req.CreateAttr("ID", id)
	req.CreateAttr("Version", "2.0")
	req.CreateAttr("IssueInstant", now.Format(timeFormat))
	req.CreateAttr("Destination", dest)
	req.CreateElement("saml:Issuer").SetText(i.SAMLEntityID())
	nid := req.CreateElement("saml:NameID")
	nid.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nid.SetText(o.NameID)
	for _, s := range o.SessionIndex {
		req.CreateElement("samlp:SessionIndex").SetText(s)
	}
	if o.Mutate != nil {
		o.Mutate(req)
	}
	key := i.rsaKey
	if o.SignWithOther != nil {
		key = o.SignWithOther
	}
	target, form, err = i.encodeSAML(doc, o.Binding, dest, "SAMLRequest", o.RelayState, key, !o.Unsigned)
	if err != nil {
		return "", nil, "", err
	}
	i.mu.Lock()
	i.pendingLogout[id] = o.SP
	i.mu.Unlock()
	return target, form, id, nil
}

// encodeSAML encodes doc for a binding, signed with key unless sign is
// false.
func (i *IdP) encodeSAML(doc *etree.Document, binding, dest, param, relayState string, key *rsa.PrivateKey, sign bool) (string, url.Values, error) {
	if binding == POST {
		if sign {
			ctx, err := dsig.NewSigningContext(key, [][]byte{i.cert.Raw})
			if err != nil {
				return "", nil, err
			}
			ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
			_ = ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
			sig, err := ctx.ConstructSignature(doc.Root(), true)
			if err != nil {
				return "", nil, err
			}
			doc.Root().InsertChildAt(1, sig)
		}
		b, err := doc.WriteToBytes()
		if err != nil {
			return "", nil, err
		}
		f := url.Values{param: {base64.StdEncoding.EncodeToString(b)}}
		if relayState != "" {
			f.Set("RelayState", relayState)
		}
		return dest, f, nil
	}
	b, err := doc.WriteToBytes()
	if err != nil {
		return "", nil, err
	}
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	fw.Write(b)
	fw.Close()
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	if sign {
		q += "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
		sum := sha256.Sum256([]byte(q))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			return "", nil, err
		}
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	sep := "?"
	if strings.Contains(dest, "?") {
		sep = "&"
	}
	return dest + sep + q, nil, nil
}

// endSAMLSessions ends the IdP sessions of nameID at sp that a logout names:
// those indexes, or all of them. The caller holds i.mu.
func (i *IdP) endSAMLSessions(sp, nameID string, indexes []string) int {
	n := 0
	for k, s := range i.samlSessions {
		if s.sp != sp || s.email != nameID {
			continue
		}
		if len(indexes) > 0 && !containsString(indexes, k) {
			continue
		}
		delete(i.samlSessions, k)
		n++
	}
	return n
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (i *IdP) sloURL() string { return i.cfg.Issuer + "/saml/slo" }

// samlSLO serves the SingleLogoutService for both bindings.
func (i *IdP) samlSLO(w http.ResponseWriter, r *http.Request) {
	binding := Redirect
	if r.Method == http.MethodPost {
		binding = POST
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusBadRequest, "bad form")
			return
		}
	}
	if !containsString(i.sloBindings(), binding) {
		httpError(w, http.StatusNotFound, "single logout is not enabled for this binding")
		return
	}
	root, relay, err := i.readSAMLLogout(r, binding)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	issuer := ""
	if iss := root.FindElement("./Issuer"); iss != nil {
		issuer = strings.TrimSpace(iss.Text())
	}
	switch root.Tag {
	case "LogoutRequest":
		i.answerLogoutRequest(w, r, root, issuer, relay, binding)
	case "LogoutResponse":
		i.mu.Lock()
		irt := root.SelectAttrValue("InResponseTo", "")
		sp, ok := i.pendingLogout[irt]
		if ok && sp == issuer {
			delete(i.pendingLogout, irt)
			status := ""
			if sc := root.FindElement("./Status/StatusCode"); sc != nil {
				status = sc.SelectAttrValue("Value", "")
			}
			i.logoutResults[irt] = status
		}
		i.mu.Unlock()
		if !ok || sp != issuer {
			httpError(w, http.StatusBadRequest, "LogoutResponse to no pending request of that service provider")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<!doctype html><title>Signed out</title><p>Signed out.</p>\n"))
	default:
		httpError(w, http.StatusBadRequest, "not a LogoutRequest or LogoutResponse")
	}
}

// readSAMLLogout decodes a logout message and checks that it is signed by
// the registered service provider it names and addressed to this endpoint.
func (i *IdP) readSAMLLogout(r *http.Request, binding string) (*etree.Element, string, error) {
	var xmlBytes []byte
	var q url.Values
	if binding == Redirect {
		var err error
		if q, err = url.ParseQuery(r.URL.RawQuery); err != nil {
			return nil, "", errors.New("bad query string")
		}
		param := "SAMLRequest"
		if q.Has("SAMLResponse") {
			param = "SAMLResponse"
		}
		raw, err := base64.StdEncoding.DecodeString(q.Get(param))
		if err != nil {
			return nil, "", errors.New(param + " is not base64")
		}
		if xmlBytes, err = io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 64<<10)); err != nil {
			return nil, "", errors.New(param + " is not deflated")
		}
	} else {
		q = r.PostForm
		v := q.Get("SAMLRequest")
		if v == "" {
			v = q.Get("SAMLResponse")
		}
		var err error
		if xmlBytes, err = base64.StdEncoding.DecodeString(v); err != nil {
			return nil, "", errors.New("message is not base64")
		}
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil || doc.Root() == nil || doc.Root().NamespaceURI() != nsProtocol {
		return nil, "", errors.New("not a SAML protocol message")
	}
	root := doc.Root()
	iss := root.FindElement("./Issuer")
	if iss == nil {
		return nil, "", errors.New("message has no Issuer")
	}
	i.mu.Lock()
	var cert *x509.Certificate
	if sp := i.serviceProvider(strings.TrimSpace(iss.Text())); sp != nil {
		cert = sp.LogoutCert
	}
	i.mu.Unlock()
	if cert == nil {
		return nil, "", errors.New("unknown service provider, or no logout certificate registered")
	}
	if root.SelectAttrValue("Destination", "") != i.sloURL() {
		return nil, "", errors.New("wrong Destination")
	}
	if binding == Redirect {
		if err := verifyLogoutQuery(r.URL.RawQuery, q, cert); err != nil {
			return nil, "", errors.New("logout message signature: " + err.Error())
		}
	} else {
		vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
		vc.Clock = dsig.NewFakeClockAt(i.cfg.Now())
		verified, err := vc.Validate(root)
		if err != nil {
			return nil, "", errors.New("logout message signature: " + err.Error())
		}
		root = verified
	}
	return root, q.Get("RelayState"), nil
}

// answerLogoutRequest ends the sessions a service provider's LogoutRequest
// names and sends the signed LogoutResponse back on the same binding.
func (i *IdP) answerLogoutRequest(w http.ResponseWriter, r *http.Request, req *etree.Element, issuer, relay, binding string) {
	nameID := ""
	if nid := req.FindElement("./NameID"); nid != nil {
		nameID = strings.TrimSpace(nid.Text())
	}
	var idx []string
	for _, el := range req.SelectElements("SessionIndex") {
		idx = append(idx, strings.TrimSpace(el.Text()))
	}
	status := statusSuccess
	if nameID == "" {
		status = statusRequester
	}
	i.mu.Lock()
	ended := 0
	if status == statusSuccess {
		ended = i.endSAMLSessions(issuer, nameID, idx)
	}
	i.received = append(i.received, ReceivedLogout{SP: issuer, NameID: nameID, SessionIndex: idx, Binding: binding, EndedSessions: ended})
	dest := i.serviceProvider(issuer).SingleLogoutURL
	i.mu.Unlock()
	if dest == "" {
		httpError(w, http.StatusBadRequest, "the service provider has no SingleLogoutService")
		return
	}
	target, form, err := i.logoutResponse(dest, req.SelectAttrValue("ID", ""), status, binding, relay)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not build the response")
		return
	}
	if form == nil {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = autoPost.Execute(w, map[string]any{"Action": target, "Fields": form})
}

func (i *IdP) logoutResponse(dest, inResponseTo, status, binding, relay string) (string, url.Values, error) {
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:LogoutResponse")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("ID", newID())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", i.cfg.Now().UTC().Format(timeFormat))
	resp.CreateAttr("Destination", dest)
	resp.CreateAttr("InResponseTo", inResponseTo)
	resp.CreateElement("saml:Issuer").SetText(i.SAMLEntityID())
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", status)
	return i.encodeSAML(doc, binding, dest, "SAMLResponse", relay, i.rsaKey, true)
}

// SAMLLogoutResponse builds a signed LogoutResponse to a request the
// service provider sp may or may not have sent, for tests of how it is
// matched: where the browser goes, as SAMLLogoutRequest returns it. An
// empty status is Success.
func (i *IdP) SAMLLogoutResponse(sp, inResponseTo, status, binding, relayState string) (string, url.Values, error) {
	i.mu.Lock()
	var dest string
	if p := i.serviceProvider(sp); p != nil {
		dest = p.SingleLogoutURL
	}
	i.mu.Unlock()
	if dest == "" {
		return "", nil, errors.New("fakeidp: no SingleLogoutService registered for that service provider")
	}
	if status == "" {
		status = statusSuccess
	}
	return i.logoutResponse(dest, inResponseTo, status, binding, relayState)
}

// verifyLogoutQuery checks an HTTP-Redirect signature (RSA-SHA256) over
// the raw, still-encoded parameters, for a request or a response.
func verifyLogoutQuery(rawQuery string, q url.Values, cert *x509.Certificate) error {
	if q.Get("SigAlg") != dsig.RSASHA256SignatureMethod {
		return errors.New("must be signed with RSA-SHA256")
	}
	raw := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(part, "=")
		raw[k] = v
	}
	param := "SAMLRequest"
	if _, ok := raw["SAMLResponse"]; ok {
		param = "SAMLResponse"
	}
	signed := param + "=" + raw[param]
	if v, ok := raw["RelayState"]; ok {
		signed += "&RelayState=" + v
	}
	signed += "&SigAlg=" + raw["SigAlg"]
	sig, err := base64.StdEncoding.DecodeString(q.Get("Signature"))
	if err != nil {
		return errors.New("the Signature parameter is not base64")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("certificate is not RSA")
	}
	sum := sha256.Sum256([]byte(signed))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
		return errors.New("signature is invalid")
	}
	return nil
}

// autoPost is the HTTP-POST binding's form (Bindings section 3.5.4).
var autoPost = template.Must(template.New("autopost").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Continue</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="{{.Action}}">
{{range $k, $v := .Fields}}<input type="hidden" name="{{$k}}" value="{{index $v 0}}">
{{end}}<noscript><button type="submit">Continue</button></noscript>
</form></body></html>`))
