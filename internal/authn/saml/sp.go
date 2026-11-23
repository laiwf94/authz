// Package saml is a SAML 2.0 service provider for the Web Browser SSO
// profile: SP-initiated AuthnRequest over HTTP-Redirect, Response over
// HTTP-POST, and the Single Logout profile over HTTP-Redirect and HTTP-POST
// (OASIS SAML 2.0 Core, Bindings and Profiles).
package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// DefaultSkew is the default allowance for clock differences.
const DefaultSkew = 2 * time.Minute

// Config describes the service provider and the identity provider it trusts.
type Config struct {
	ProviderID string // wicket's id for this IdP, used in identities
	EntityID   string // SP entity id
	ACSURL     string // assertion consumer service URL
	// SLOURL is the SP's SingleLogoutService, for both bindings. Single
	// logout also needs Key and an IdP that lists a SingleLogoutService.
	SLOURL       string
	IdP          *IdPMetadata
	Key          *rsa.PrivateKey   // SP key: decrypts assertions, signs requests
	Cert         *x509.Certificate // SP certificate published in metadata
	SignRequests bool
	NameIDFormat string
	EmailAttr    string
	NameAttr     string
	GroupsAttr   string
	// Claims names the attributes a login keeps in Identity.Claims, for
	// the claim conditions of the apps that accept this provider
	// (policy.Policy.ClaimNames). Others are not kept.
	Claims []string
	Skew   time.Duration
	Now    func() time.Time
	Replay *ReplayCache
}

// SP is a configured service provider. It is safe for concurrent use.
type SP struct {
	cfg Config
}

// New validates the configuration.
func New(cfg Config) (*SP, error) {
	if cfg.EntityID == "" || cfg.ACSURL == "" {
		return nil, errors.New("saml: entity id and ACS URL are required")
	}
	if cfg.IdP == nil || len(cfg.IdP.Certs) == 0 || cfg.IdP.SSOURL == "" {
		return nil, errors.New("saml: identity provider metadata with a signing certificate and SSO URL is required")
	}
	if (cfg.Key == nil) != (cfg.Cert == nil) {
		return nil, errors.New("saml: SP key and certificate go together")
	}
	if cfg.Key != nil && cfg.Key.N.BitLen() < 2048 {
		return nil, errors.New("saml: SP RSA key must be at least 2048 bits")
	}
	if cfg.SignRequests && cfg.Key == nil {
		return nil, errors.New("saml: signing requests needs an SP key")
	}
	if cfg.IdP.WantRequestsSigned && !cfg.SignRequests {
		return nil, errors.New("saml: the identity provider wants signed requests; set sign_requests and an SP key")
	}
	if cfg.NameIDFormat == "" {
		cfg.NameIDFormat = NameIDUnspecified
	}
	if cfg.Skew <= 0 {
		cfg.Skew = DefaultSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Replay == nil {
		cfg.Replay = NewReplayCache(0, cfg.Now)
	}
	return &SP{cfg: cfg}, nil
}

// ID returns the provider id from the configuration.
func (sp *SP) ID() string { return sp.cfg.ProviderID }

// NewRequestID returns a fresh AuthnRequest ID: "_" and 128 random bits.
func NewRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "_" + hex.EncodeToString(b[:])
}

// AuthnRequestURL builds the HTTP-Redirect binding URL for a new request
// with this ID and relay state (SAML Bindings section 3.4).
func (sp *SP) AuthnRequestURL(requestID, relayState string) (string, error) {
	return sp.AuthnRequestURLWith(requestID, relayState, AuthnOptions{})
}

// AuthnOptions asks the IdP for a fresh or stronger authentication (SAML
// Core section 3.4.1).
type AuthnOptions struct {
	// ForceAuthn makes the IdP authenticate the user again rather than
	// rely on its own session.
	ForceAuthn bool
	// ClassRefs is a RequestedAuthnContext of these AuthnContextClassRef
	// values, compared exactly; empty sends none.
	ClassRefs []string
}

// AuthnRequestURLWith is AuthnRequestURL with ForceAuthn and a
// RequestedAuthnContext.
func (sp *SP) AuthnRequestURLWith(requestID, relayState string, o AuthnOptions) (string, error) {
	if len(relayState) > 80 {
		return "", errors.New("saml: RelayState longer than 80 bytes")
	}
	doc := etree.NewDocument()
	req := doc.CreateElement("samlp:AuthnRequest")
	req.CreateAttr("xmlns:samlp", NSProtocol)
	req.CreateAttr("xmlns:saml", NSAssertion)
	req.CreateAttr("ID", requestID)
	req.CreateAttr("Version", "2.0")
	req.CreateAttr("IssueInstant", sp.cfg.Now().UTC().Format(timeFormat))
	req.CreateAttr("Destination", sp.cfg.IdP.SSOURL)
	req.CreateAttr("AssertionConsumerServiceURL", sp.cfg.ACSURL)
	req.CreateAttr("ProtocolBinding", BindingPOST)
	if o.ForceAuthn {
		req.CreateAttr("ForceAuthn", "true")
	}
	req.CreateElement("saml:Issuer").SetText(sp.cfg.EntityID)
	pol := req.CreateElement("samlp:NameIDPolicy")
	pol.CreateAttr("Format", sp.cfg.NameIDFormat)
	pol.CreateAttr("AllowCreate", "true")
	// RequestedAuthnContext follows NameIDPolicy in the schema.
	if len(o.ClassRefs) > 0 {
		rac := req.CreateElement("samlp:RequestedAuthnContext")
		rac.CreateAttr("Comparison", "exact")
		for _, c := range o.ClassRefs {
			rac.CreateElement("saml:AuthnContextClassRef").SetText(c)
		}
	}
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	fw.Write(raw)
	fw.Close()

	// The signed string is the query in exactly this order (Bindings
	// section 3.4.4.1), so it is assembled by hand.
	q := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	if sp.cfg.SignRequests {
		if q, err = sp.signQuery(q); err != nil {
			return "", err
		}
	}
	sep := "?"
	if strings.Contains(sp.cfg.IdP.SSOURL, "?") {
		sep = "&"
	}
	return sp.cfg.IdP.SSOURL + sep + q, nil
}

// timeFormat is xs:dateTime in UTC as SAML uses it.
const timeFormat = "2006-01-02T15:04:05Z"

// Metadata renders the SP's metadata document for the identity provider.
func (sp *SP) Metadata() ([]byte, error) {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", NSMetadata)
	ed.CreateAttr("xmlns:ds", NSDSig)
	ed.CreateAttr("entityID", sp.cfg.EntityID)
	sd := ed.CreateElement("md:SPSSODescriptor")
	sd.CreateAttr("AuthnRequestsSigned", fmt.Sprint(sp.cfg.SignRequests))
	sd.CreateAttr("WantAssertionsSigned", "true")
	sd.CreateAttr("protocolSupportEnumeration", NSProtocol)
	if sp.cfg.Cert != nil {
		for _, use := range []string{"signing", "encryption"} {
			kd := sd.CreateElement("md:KeyDescriptor")
			kd.CreateAttr("use", use)
			kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
				SetText(base64.StdEncoding.EncodeToString(sp.cfg.Cert.Raw))
			if use == "encryption" {
				for _, alg := range []string{EncAES256GCM, EncAES128GCM, KeyRSAOAEP, KeyRSAOAEP11} {
					kd.CreateElement("md:EncryptionMethod").CreateAttr("Algorithm", alg)
				}
			}
		}
	}
	if sp.LogoutEnabled() {
		// SingleLogoutService comes before NameIDFormat in SSODescriptorType.
		for _, b := range []string{BindingRedirect, BindingPOST} {
			slo := sd.CreateElement("md:SingleLogoutService")
			slo.CreateAttr("Binding", b)
			slo.CreateAttr("Location", sp.cfg.SLOURL)
		}
	}
	sd.CreateElement("md:NameIDFormat").SetText(sp.cfg.NameIDFormat)
	acs := sd.CreateElement("md:AssertionConsumerService")
	acs.CreateAttr("Binding", BindingPOST)
	acs.CreateAttr("Location", sp.cfg.ACSURL)
	acs.CreateAttr("index", "0")
	acs.CreateAttr("isDefault", "true")
	doc.Indent(2)
	return doc.WriteToBytes()
}
