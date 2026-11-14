package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IdPMetadata is what the SP needs from an identity provider's metadata.
type IdPMetadata struct {
	EntityID           string
	SSOURL             string // HTTP-Redirect SingleSignOnService
	Certs              []*x509.Certificate
	WantRequestsSigned bool
}

// ParseIdPMetadata reads an EntityDescriptor with an IDPSSODescriptor. The
// document is trusted as configuration: it must come from a file the
// operator controls or an https URL.
func ParseIdPMetadata(b []byte) (*IdPMetadata, error) {
	doc, err := parseStrict(b)
	if err != nil {
		return nil, fmt.Errorf("saml metadata: %w", err)
	}
	ed := doc.Root()
	if !is(ed, NSMetadata, "EntityDescriptor") {
		return nil, errors.New("saml metadata: root must be md:EntityDescriptor")
	}
	m := &IdPMetadata{EntityID: attr(ed, "entityID")}
	if m.EntityID == "" {
		return nil, errors.New("saml metadata: entityID is missing")
	}
	idp, err := child(ed, NSMetadata, "IDPSSODescriptor")
	if err != nil || idp == nil {
		return nil, errors.New("saml metadata: need exactly one IDPSSODescriptor")
	}
	if !strings.Contains(attr(idp, "protocolSupportEnumeration"), NSProtocol) {
		return nil, errors.New("saml metadata: IdP does not support SAML 2.0")
	}
	m.WantRequestsSigned = attr(idp, "WantAuthnRequestsSigned") == "true"
	for _, kd := range children(idp, NSMetadata, "KeyDescriptor") {
		if use := attr(kd, "use"); use != "" && use != "signing" {
			continue
		}
		ki, _ := child(kd, NSDSig, "KeyInfo")
		if ki == nil {
			continue
		}
		for _, xd := range children(ki, NSDSig, "X509Data") {
			for _, xc := range children(xd, NSDSig, "X509Certificate") {
				t, err := text(xc)
				if err != nil {
					return nil, fmt.Errorf("saml metadata: %w", err)
				}
				cert, err := ParseCertificate(t)
				if err != nil {
					return nil, fmt.Errorf("saml metadata: %w", err)
				}
				m.Certs = append(m.Certs, cert)
			}
		}
	}
	if len(m.Certs) == 0 {
		return nil, errors.New("saml metadata: no signing certificate")
	}
	for _, sso := range children(idp, NSMetadata, "SingleSignOnService") {
		if attr(sso, "Binding") == BindingRedirect {
			m.SSOURL = attr(sso, "Location")
			break
		}
	}
	u, err := url.Parse(m.SSOURL)
	if m.SSOURL == "" || err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("saml metadata: need an https SingleSignOnService with the HTTP-Redirect binding")
	}
	return m, nil
}

// ParseCertificate decodes a base64 DER certificate as found in XML.
func ParseCertificate(b64 string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	if err != nil {
		return nil, errors.New("certificate is not base64")
	}
	return x509.ParseCertificate(der)
}

// FetchIdPMetadata downloads and parses metadata from an https URL.
func FetchIdPMetadata(ctx context.Context, client *http.Client, u string) (*IdPMetadata, error) {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" {
		return nil, errors.New("saml metadata URL must be https")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching saml metadata: %w", err)
	}
	defer resp.Body.Close()
	// A response that completes after the deadline is no answer: the
	// transport can still deliver one the server wrote only because it saw
	// the client give up, such as an empty 200 (#234).
	late := func() error {
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("fetching saml metadata: %w", cerr)
		}
		return nil
	}
	if err := late(); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching saml metadata: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxXMLBytes+1))
	if lerr := late(); lerr != nil {
		return nil, lerr
	}
	if err != nil {
		return nil, fmt.Errorf("fetching saml metadata: %w", err)
	}
	return ParseIdPMetadata(b)
}
