// Package fakeidp implements "authz fakeidp", the test identity provider
// that was the fakeidp command. It speaks OpenID Connect and SAML 2.0, for
// tests and the demo, and is not for production use. Its flags, config file
// and output are fakeidp's, unchanged:
//
//	authz fakeidp -config fakeidp.json [-addr :9443] [-tls-cert cert.pem -tls-key key.pem]
//	authz fakeidp gencert -dir DIR -hosts localhost,host.docker.internal
//
// The config file lists the issuer URL, OpenID Connect clients and SAML
// service providers; see examples/fakeidp.json. Client secrets come from
// the environment variable named by secret_env. The demo users are alice,
// bob and carol (passwords alice-pass, bob-pass, carol-pass).
//
// gencert writes a throwaway CA (ca.pem), a TLS certificate for the hosts
// (tls.pem, tls-key.pem) and an RSA key pair for a SAML service provider
// (sp.pem, sp-key.pem).
package fakeidp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/authn/fakeidp"
)

// Summary is the one-line description shown in "authz help fakeidp".
const Summary = "run a test OpenID Connect and SAML identity provider (not for production)"

const usageText = `usage: authz fakeidp -config fakeidp.json [-addr :9443] [-tls-cert cert.pem -tls-key key.pem]
       authz fakeidp gencert -dir DIR [-hosts localhost,host.docker.internal]

Runs a test identity provider speaking OpenID Connect and SAML 2.0, for tests
and the demo; it is not for production use. The config file lists the issuer,
OpenID Connect clients and SAML service providers (see examples/fakeidp.json);
client secrets come from the environment variables named by secret_env.
gencert writes a throwaway CA, a TLS certificate for the hosts and an RSA key
pair for a SAML service provider into DIR.

Logs are JSON lines on standard error. SIGINT or SIGTERM stops it. Exit codes:
0 success, 1 when it cannot start or fails, 2 a usage error.
`

// usageError marks a command line the flag package refused, so Run can
// exit 2 for it and 1 for everything else.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

// Run is the "authz fakeidp" subcommand. It takes fakeidp's arguments and
// returns 0 on a clean stop (or -h), 1 when it cannot start or fails, and 2
// for flags it does not define.
func Run(ctx context.Context, args []string, getenv func(string) string, _ io.Reader, _, stderr io.Writer) int {
	err := run(ctx, args, getenv, stderr, nil)
	var ue usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &ue):
		return 2 // the flag package has printed the problem and the usage
	}
	fmt.Fprintln(stderr, "authz fakeidp:", err)
	return 1
}

type fileConfig struct {
	Issuer  string `json:"issuer"`
	Clients []struct {
		ID                     string   `json:"id"`
		SecretEnv              string   `json:"secret_env"`
		RedirectURIs           []string `json:"redirect_uris"`
		PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	} `json:"clients"`
	ServiceProviders []struct {
		EntityID        string `json:"entity_id"`
		ACSURL          string `json:"acs_url"`
		SignResponse    bool   `json:"sign_response"`
		SignAssertion   bool   `json:"sign_assertion"`
		EncryptCertFile string `json:"encrypt_cert_file"`
		RequestCertFile string `json:"request_cert_file"`
	} `json:"service_providers"`
}

func loadConfig(path string, getenv func(string) string) (fakeidp.Config, error) {
	var cfg fakeidp.Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	var fc fileConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		return cfg, fmt.Errorf("%s: %v", path, err)
	}
	cfg.Issuer = fc.Issuer
	for _, c := range fc.Clients {
		secret := getenv(c.SecretEnv)
		if secret == "" {
			return cfg, fmt.Errorf("client %s: environment variable %q is empty", c.ID, c.SecretEnv)
		}
		cfg.Clients = append(cfg.Clients, fakeidp.Client{ID: c.ID, Secret: secret, RedirectURIs: c.RedirectURIs,
			PostLogoutRedirectURIs: c.PostLogoutRedirectURIs})
	}
	for _, sp := range fc.ServiceProviders {
		p := fakeidp.ServiceProvider{EntityID: sp.EntityID, ACSURL: sp.ACSURL, SignResponse: sp.SignResponse,
			SignAssertion: sp.SignAssertion}
		if sp.EncryptCertFile != "" {
			if p.EncryptCert, err = readCert(sp.EncryptCertFile); err != nil {
				return cfg, err
			}
		}
		if sp.RequestCertFile != "" {
			if p.RequestCert, err = readCert(sp.RequestCertFile); err != nil {
				return cfg, err
			}
		}
		cfg.ServiceProviders = append(cfg.ServiceProviders, p)
	}
	return cfg, nil
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no CERTIFICATE PEM block", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func run(ctx context.Context, args []string, getenv func(string) string, logOut io.Writer, ready func(addr string)) error {
	if len(args) > 0 && args[0] == "gencert" {
		return gencert(args[1:], logOut)
	}
	fs := flag.NewFlagSet("fakeidp", flag.ContinueOnError)
	fs.SetOutput(logOut)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usageText) }
	cfgPath := fs.String("config", "", "path of the JSON config file (required)")
	addr := fs.String("addr", ":9443", "listen address")
	tlsCert := fs.String("tls-cert", "", "TLS certificate PEM (serve HTTPS when set)")
	tlsKey := fs.String("tls-key", "", "TLS key PEM")
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	if *cfgPath == "" {
		return errors.New("-config is required")
	}
	cfg, err := loadConfig(*cfgPath, getenv)
	if err != nil {
		return err
	}
	idp, err := fakeidp.New(cfg)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(logOut, nil))
	hs := &http.Server{Handler: logged(log, idp), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	log.Info("fakeidp listening", "addr", ln.Addr().String(), "issuer", cfg.Issuer, "tls", *tlsCert != "")
	if ready != nil {
		ready(ln.Addr().String())
	}
	errc := make(chan error, 1)
	go func() {
		if *tlsCert != "" {
			errc <- hs.ServeTLS(ln, *tlsCert, *tlsKey)
		} else {
			errc <- hs.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}

func logged(log *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info("request", "method", r.Method, "path", r.URL.Path)
		h.ServeHTTP(w, r)
	})
}

func gencert(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("gencert", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usageText) }
	dir := fs.String("dir", "", "output directory (required)")
	hosts := fs.String("hosts", "localhost", "comma-separated DNS names and IPs for the TLS certificate")
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	if *dir == "" {
		return errors.New("gencert: -dir is required")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "fakeidp demo CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "fakeidp demo TLS"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, h := range strings.Split(*hosts, ",") {
		if ip := net.ParseIP(h); ip != nil {
			leafTmpl.IPAddresses = append(leafTmpl.IPAddresses, ip)
		} else if h != "" {
			leafTmpl.DNSNames = append(leafTmpl.DNSNames, h)
		}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	spKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	spCert, err := fakeidp.SelfSignedCert(spKey, "wicket demo SP", now)
	if err != nil {
		return err
	}
	leafKeyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	spKeyDER, _ := x509.MarshalPKCS8PrivateKey(spKey)
	files := []struct {
		name, typ string
		der       []byte
	}{
		{"ca.pem", "CERTIFICATE", caDER},
		{"tls.pem", "CERTIFICATE", leafDER},
		{"tls-key.pem", "PRIVATE KEY", leafKeyDER},
		{"sp.pem", "CERTIFICATE", spCert.Raw},
		{"sp-key.pem", "PRIVATE KEY", spKeyDER},
	}
	for _, f := range files {
		b := pem.EncodeToMemory(&pem.Block{Type: f.typ, Bytes: f.der})
		if err := os.WriteFile(filepath.Join(*dir, f.name), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	return n
}
