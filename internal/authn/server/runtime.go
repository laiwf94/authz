package server

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/authn/keyfile"
	"github.com/laiwf94/authz/internal/authn/oidc"
	"github.com/laiwf94/authz/internal/authn/policy"
	"github.com/laiwf94/authz/internal/authn/redirect"
	"github.com/laiwf94/authz/internal/authn/saml"
)

// runtime is everything built from one configuration file. A reload builds
// a new one and swaps it in atomically; requests in flight keep the one
// they started with.
type runtime struct {
	cfg        *config.Config
	public     *url.URL
	providers  map[string]*provider
	apps       map[string]*app
	appsByHost map[string]*app
	redirects  *redirect.Validator
}

type provider struct {
	id, kind, display string
	oidc              *oidc.Provider
	saml              *saml.SP
	postLogout        string
	reval             revalidation
}

type app struct {
	id         string
	providers  []string
	policy     *policy.Compiled
	defaultURL string
}

// buildOptions carries what tests replace.
type buildOptions struct {
	// httpClient returns the back-channel client for a provider; nil uses
	// one built from the provider's ca_file.
	httpClient func(p *config.Provider) (*http.Client, error)
	now        func() time.Time
	replay     *saml.ReplayCache
}

func buildRuntime(ctx context.Context, cfg *config.Config, o buildOptions) (*runtime, error) {
	rt := &runtime{cfg: cfg, public: cfg.Public, providers: map[string]*provider{}, apps: map[string]*app{},
		appsByHost: map[string]*app{}}
	skew := time.Duration(cfg.ClockSkew)
	for i := range cfg.Providers {
		pc := &cfg.Providers[i]
		client, err := providerClient(pc, o)
		if err != nil {
			return nil, fmt.Errorf("provider %s: %w", pc.ID, err)
		}
		p := &provider{id: pc.ID, kind: pc.Type, display: pc.DisplayName, postLogout: pc.PostLogoutRedirectURL}
		switch pc.Type {
		case config.ProviderOIDC:
			p.oidc, err = oidc.New(oidc.Config{
				ID: pc.ID, Issuer: pc.Issuer, ClientID: pc.ClientID, ClientSecret: pc.ClientSecret,
				ClientAuth: pc.ClientAuth, RedirectURL: cfg.PublicURL + "/callback/" + pc.ID, Scopes: pc.Scopes,
				Algorithms: pc.Algorithms, EmailClaim: pc.EmailClaim, NameClaim: pc.NameClaim,
				GroupsClaim: pc.GroupsClaim, UseUserinfo: pc.Userinfo, TrustedAudiences: pc.TrustedAudiences,
				Skew: skew, HTTPClient: client, Now: o.now,
			})
			p.reval = revalidationOf(pc.Revalidate)
		case config.ProviderSAML:
			p.saml, err = buildSAML(ctx, cfg, pc, client, skew, o)
		}
		if err != nil {
			return nil, fmt.Errorf("provider %s: %w", pc.ID, err)
		}
		rt.providers[pc.ID] = p
	}
	var hosts []string
	for _, ac := range cfg.Apps {
		a := &app{id: ac.ID, providers: ac.Providers, defaultURL: ac.DefaultURL, policy: policy.Compile(policy.Rule{
			Providers: ac.Providers, AnyUser: ac.Allow.AnyUser, Emails: ac.Allow.Emails,
			EmailDomains: ac.Allow.EmailDomains, Groups: ac.Allow.Groups,
		})}
		rt.apps[a.id] = a
		for _, h := range ac.Hosts {
			rt.appsByHost[h] = a
			hosts = append(hosts, h)
		}
	}
	var err error
	if rt.redirects, err = redirect.New(append(hosts, cfg.RedirectHosts...), cfg.Public); err != nil {
		return nil, err
	}
	for _, a := range rt.apps {
		if _, err := rt.redirects.Validate(a.defaultURL); err != nil {
			return nil, fmt.Errorf("app %s: default_url host is not an app host or redirect host", a.id)
		}
	}
	return rt, nil
}

func providerClient(pc *config.Provider, o buildOptions) (*http.Client, error) {
	if o.httpClient != nil {
		return o.httpClient(pc)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if pc.CAFile != "" {
		pool, _, err := keyfile.CAPool(pc.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		// The file replaces the system roots: the provider is pinned to
		// the private CA.
		tr.TLSClientConfig.RootCAs = pool
	}
	return oidc.NewHTTPClient(tr), nil
}

func buildSAML(ctx context.Context, cfg *config.Config, pc *config.Provider, client *http.Client, skew time.Duration, o buildOptions) (*saml.SP, error) {
	var md *saml.IdPMetadata
	var err error
	if pc.IdPMetadataFile != "" {
		b, rerr := os.ReadFile(pc.IdPMetadataFile)
		if rerr != nil {
			return nil, fmt.Errorf("idp_metadata_file: %w", rerr)
		}
		md, err = saml.ParseIdPMetadata(b)
	} else {
		md, err = saml.FetchIdPMetadata(ctx, client, pc.IdPMetadataURL)
	}
	if err != nil {
		return nil, err
	}
	var key *rsa.PrivateKey
	var cert *x509.Certificate
	if pc.SPKeyFile != "" {
		if key, cert, err = keyfile.KeyPair(pc.SPKeyFile, pc.SPCertFile); err != nil {
			return nil, fmt.Errorf("sp_key_file, sp_cert_file: %w", err)
		}
	}
	entityID := pc.EntityID
	if entityID == "" {
		entityID = cfg.PublicURL + "/saml/" + pc.ID + "/metadata"
	}
	emailAttr, groupsAttr := pc.EmailAttribute, pc.GroupsAttribute
	if emailAttr == "" {
		emailAttr = "email"
	}
	if groupsAttr == "" {
		groupsAttr = "groups"
	}
	return saml.New(saml.Config{
		ProviderID: pc.ID, EntityID: entityID, ACSURL: cfg.PublicURL + "/saml/" + pc.ID + "/acs", IdP: md,
		Key: key, Cert: cert, SignRequests: pc.SignRequests, NameIDFormat: pc.NameIDFormat,
		EmailAttr: emailAttr, NameAttr: pc.NameAttribute, GroupsAttr: groupsAttr, Skew: skew, Now: o.now,
		Replay: o.replay,
	})
}

// appFor finds the app by explicit id, or else by host.
func (rt *runtime) appFor(id, host string) *app {
	if id != "" {
		return rt.apps[id]
	}
	h := strings.ToLower(host)
	if a := rt.appsByHost[h]; a != nil {
		return a
	}
	// "host:443" and "host" name the same https origin.
	if strings.HasSuffix(h, ":443") {
		return rt.appsByHost[strings.TrimSuffix(h, ":443")]
	}
	return rt.appsByHost[h+":443"]
}
