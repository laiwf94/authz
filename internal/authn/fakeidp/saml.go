package fakeidp

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" // MGF1-SHA1 for RSA-OAEP
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAML namespaces and identifiers (duplicated from the SP package on purpose:
// the fake must not share code with the thing it tests).
const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"
	nsXEnc      = "http://www.w3.org/2001/04/xmlenc#"
	timeFormat  = "2006-01-02T15:04:05Z"
)

// SAMLEntityID is the IdP's entity id.
func (i *IdP) SAMLEntityID() string { return i.cfg.Issuer + "/saml/metadata" }

func (i *IdP) samlMetadata(w http.ResponseWriter, _ *http.Request) {
	doc := etree.NewDocument()
	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("xmlns:ds", nsDSig)
	ed.CreateAttr("entityID", i.SAMLEntityID())
	idp := ed.CreateElement("md:IDPSSODescriptor")
	idp.CreateAttr("protocolSupportEnumeration", nsProtocol)
	kd := idp.CreateElement("md:KeyDescriptor")
	kd.CreateAttr("use", "signing")
	kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(i.cert.Raw))
	idp.CreateElement("md:NameIDFormat").SetText("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	sso := idp.CreateElement("md:SingleSignOnService")
	sso.CreateAttr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
	sso.CreateAttr("Location", i.cfg.Issuer+"/saml/sso")
	doc.Indent(2)
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	doc.WriteTo(w)
}

// Metadata returns the IdP metadata document.
func (i *IdP) Metadata() []byte {
	rec := &bufferWriter{}
	i.samlMetadata(rec, nil)
	return rec.buf.Bytes()
}

type bufferWriter struct {
	buf bytes.Buffer
	h   http.Header
}

func (b *bufferWriter) Header() http.Header {
	if b.h == nil {
		b.h = http.Header{}
	}
	return b.h
}
func (b *bufferWriter) Write(p []byte) (int, error) { return b.buf.Write(p) }
func (b *bufferWriter) WriteHeader(int)             {}

func (i *IdP) serviceProvider(entityID string) *ServiceProvider {
	for k := range i.cfg.ServiceProviders {
		if i.cfg.ServiceProviders[k].EntityID == entityID {
			return &i.cfg.ServiceProviders[k]
		}
	}
	return nil
}

type authnRequest struct {
	id         string
	sp         *ServiceProvider
	acs        string
	relayState string
}

// parseAuthnRequest decodes an HTTP-Redirect AuthnRequest from the raw query
// string and checks it against the registered service provider.
func (i *IdP) parseAuthnRequest(rawQuery string) (*authnRequest, error) {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, errors.New("bad query string")
	}
	raw, err := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
	if err != nil {
		return nil, errors.New("SAMLRequest is not base64")
	}
	xmlBytes, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 64<<10))
	if err != nil {
		return nil, errors.New("SAMLRequest is not deflated")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, errors.New("SAMLRequest is not XML")
	}
	root := doc.Root()
	if root == nil || root.Tag != "AuthnRequest" || root.NamespaceURI() != nsProtocol {
		return nil, errors.New("not an AuthnRequest")
	}
	iss := root.FindElement("./Issuer")
	if iss == nil {
		return nil, errors.New("AuthnRequest has no Issuer")
	}
	sp := i.serviceProvider(strings.TrimSpace(iss.Text()))
	if sp == nil {
		return nil, errors.New("unknown service provider")
	}
	acs := root.SelectAttrValue("AssertionConsumerServiceURL", sp.ACSURL)
	if acs != sp.ACSURL {
		return nil, errors.New("AssertionConsumerServiceURL is not registered")
	}
	if dest := root.SelectAttrValue("Destination", ""); dest != i.cfg.Issuer+"/saml/sso" {
		return nil, errors.New("wrong Destination")
	}
	if sp.RequestCert != nil {
		if err := verifyRedirectSignature(rawQuery, q, sp); err != nil {
			return nil, err
		}
	}
	return &authnRequest{id: root.SelectAttrValue("ID", ""), sp: sp, acs: acs, relayState: q.Get("RelayState")}, nil
}

// verifyRedirectSignature checks the query-string signature of the
// HTTP-Redirect binding over the raw, still-encoded parameters.
func verifyRedirectSignature(rawQuery string, q url.Values, sp *ServiceProvider) error {
	if q.Get("SigAlg") != dsig.RSASHA256SignatureMethod {
		return errors.New("AuthnRequest must be signed with RSA-SHA256")
	}
	raw := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(part, "=")
		raw[k] = v
	}
	signed := "SAMLRequest=" + raw["SAMLRequest"]
	if v, ok := raw["RelayState"]; ok {
		signed += "&RelayState=" + v
	}
	signed += "&SigAlg=" + raw["SigAlg"]
	sig, err := base64.StdEncoding.DecodeString(q.Get("Signature"))
	if err != nil {
		return errors.New("the Signature parameter is not base64")
	}
	pub, ok := sp.RequestCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("request certificate is not RSA")
	}
	sum := sha256.Sum256([]byte(signed))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
		return errors.New("AuthnRequest signature is invalid")
	}
	return nil
}

func (i *IdP) samlForm(w http.ResponseWriter, r *http.Request) {
	if _, err := i.parseAuthnRequest(r.URL.RawQuery); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The form carries the original query, so the POST checks the request
	// and its signature again.
	renderLogin(w, http.StatusOK, loginView{Action: i.cfg.Issuer + "/saml/sso", Protocol: "SAML 2.0",
		Hidden: map[string]string{"query": r.URL.RawQuery}})
}

var postForm = template.Must(template.New("post").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Continue</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="{{.ACS}}">
<input type="hidden" name="SAMLResponse" value="{{.Response}}">
<input type="hidden" name="RelayState" value="{{.RelayState}}">
<noscript><button type="submit">Continue</button></noscript>
</form></body></html>`))

func (i *IdP) samlSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		httpError(w, http.StatusBadRequest, "bad form")
		return
	}
	f := r.PostForm
	req, err := i.parseAuthnRequest(f.Get("query"))
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, ok := i.user(f.Get("username"), f.Get("password"))
	if !ok {
		renderLogin(w, http.StatusUnauthorized, loginView{Action: i.cfg.Issuer + "/saml/sso", Protocol: "SAML 2.0",
			Error: "Wrong username or password.", Hidden: map[string]string{"query": f.Get("query")}})
		return
	}
	resp, err := i.SAMLResponse(ResponseOptions{SP: *req.sp, InResponseTo: req.id, User: *u})
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not build the response")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = postForm.Execute(w, map[string]string{"ACS": req.acs, "Response": resp, "RelayState": req.relayState})
}

// ResponseOptions controls SAMLResponseDoc.
type ResponseOptions struct {
	SP           ServiceProvider
	InResponseTo string
	User         User
	// Lifetime of the assertion (default 5 minutes).
	Lifetime time.Duration
	// EncryptCBC encrypts with AES-256-CBC instead of AES-256-GCM.
	EncryptCBC bool
	// BeforeSign, when set, may change the assertion before it is signed.
	BeforeSign func(assertion *etree.Element)
}

// SAMLResponse builds a signed (and, if configured, encrypted) response and
// returns it base64 encoded, as the HTTP-POST binding sends it.
func (i *IdP) SAMLResponse(o ResponseOptions) (string, error) {
	doc, err := i.SAMLResponseDoc(o)
	if err != nil {
		return "", err
	}
	b, err := doc.WriteToBytes()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "_" + hex.EncodeToString(b[:])
}

func (i *IdP) signingContext() *dsig.SigningContext {
	ctx, _ := dsig.NewSigningContext(i.rsaKey, [][]byte{i.cert.Raw})
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	_ = ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	return ctx
}

// sign signs el and moves the signature right after Issuer, where the SAML
// schema puts it.
func (i *IdP) sign(el *etree.Element) (*etree.Element, error) {
	sig, err := i.signingContext().ConstructSignature(el, true)
	if err != nil {
		return nil, err
	}
	signed := el.Copy()
	signed.InsertChildAt(1, sig)
	return signed, nil
}

// SAMLResponseDoc builds the response document.
func (i *IdP) SAMLResponseDoc(o ResponseOptions) (*etree.Document, error) {
	now := i.cfg.Now().UTC()
	life := o.Lifetime
	if life == 0 {
		life = 5 * time.Minute
	}
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsAssertion)
	a.CreateAttr("ID", newID())
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", now.Format(timeFormat))
	a.CreateElement("saml:Issuer").SetText(i.SAMLEntityID())
	subj := a.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	nid.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nid.SetText(o.User.Email)
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("InResponseTo", o.InResponseTo)
	scd.CreateAttr("NotOnOrAfter", now.Add(life).Format(timeFormat))
	scd.CreateAttr("Recipient", o.SP.ACSURL)
	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", now.Add(-30*time.Second).Format(timeFormat))
	cond.CreateAttr("NotOnOrAfter", now.Add(life).Format(timeFormat))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(o.SP.EntityID)
	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", now.Format(timeFormat))
	as.CreateAttr("SessionIndex", newID())
	as.CreateAttr("SessionNotOnOrAfter", now.Add(8*time.Hour).Format(timeFormat))
	as.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").
		SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	st := a.CreateElement("saml:AttributeStatement")
	addAttr := func(name string, values ...string) {
		at := st.CreateElement("saml:Attribute")
		at.CreateAttr("Name", name)
		for _, v := range values {
			at.CreateElement("saml:AttributeValue").SetText(v)
		}
	}
	addAttr("email", o.User.Email)
	addAttr("displayName", o.User.Name)
	addAttr("groups", o.User.Groups...)
	if o.BeforeSign != nil {
		o.BeforeSign(a)
	}
	if o.SP.SignAssertion {
		var err error
		if a, err = i.sign(a); err != nil {
			return nil, err
		}
	}

	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("ID", newID())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", now.Format(timeFormat))
	resp.CreateAttr("Destination", o.SP.ACSURL)
	resp.CreateAttr("InResponseTo", o.InResponseTo)
	resp.CreateElement("saml:Issuer").SetText(i.SAMLEntityID())
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").
		CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	if o.SP.EncryptCert != nil {
		ea, err := encryptAssertion(a, o.SP, o.EncryptCBC)
		if err != nil {
			return nil, err
		}
		resp.AddChild(ea)
	} else {
		resp.AddChild(a)
	}
	if o.SP.SignResponse {
		var err error
		if resp, err = i.sign(resp); err != nil {
			return nil, err
		}
	}
	doc := etree.NewDocument()
	doc.SetRoot(resp)
	return doc, nil
}

// encryptAssertion encrypts the assertion to the SP certificate with
// AES-256-GCM (or CBC) and RSA-OAEP (MGF1 with SHA-1, SHA-256 digest).
func encryptAssertion(a *etree.Element, sp ServiceProvider, useCBC bool) (*etree.Element, error) {
	pub, ok := sp.EncryptCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("encryption certificate is not RSA")
	}
	d := etree.NewDocument()
	d.SetRoot(a.Copy())
	plain, err := d.WriteToBytes()
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	var ct []byte
	alg := "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	if useCBC {
		alg = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
		pad := aes.BlockSize - len(plain)%aes.BlockSize
		padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
		ct = make([]byte, aes.BlockSize+len(padded))
		_, _ = rand.Read(ct[:aes.BlockSize])
		cipher.NewCBCEncrypter(block, ct[:aes.BlockSize]).CryptBlocks(ct[aes.BlockSize:], padded)
	} else {
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		_, _ = rand.Read(nonce)
		ct = gcm.Seal(nonce, nonce, plain, nil)
	}
	wrapped, err := rsa.EncryptOAEPWithOptions(rand.Reader, pub, key, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA1})
	if err != nil {
		return nil, fmt.Errorf("wrapping key: %w", err)
	}
	ea := etree.NewElement("saml:EncryptedAssertion")
	ed := ea.CreateElement("xenc:EncryptedData")
	ed.CreateAttr("xmlns:xenc", nsXEnc)
	ed.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
	ed.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", alg)
	ki := ed.CreateElement("ds:KeyInfo")
	ki.CreateAttr("xmlns:ds", nsDSig)
	ek := ki.CreateElement("xenc:EncryptedKey")
	em := ek.CreateElement("xenc:EncryptionMethod")
	em.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")
	em.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	ek.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(wrapped))
	ed.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(ct))
	return ea, nil
}
