package httpserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// DefaultCertCheck is how often a TLS listener looks at its certificate
// files for a renewal.
const DefaultCertCheck = 10 * time.Second

// TLSFiles names the PEM files a TLS listener serves with.
type TLSFiles struct {
	CertFile string
	KeyFile  string
	// ClientCAFile, when set, makes every listener require a client
	// certificate signed by one of these CAs (mutual TLS).
	ClientCAFile string
	// CheckEvery is how often a handshake may look for renewed files; zero
	// is DefaultCertCheck. A renewal that fails to load keeps the
	// certificate in use.
	CheckEvery time.Duration

	now func() time.Time // tests
}

// The platform's TLS defaults: TLS 1.2 or later, and Go's defaults for the
// rest (forward-secret AEAD cipher suites only, the hybrid post-quantum key
// exchange first), with HTTP/2 offered.
func (f *TLSFiles) config() (*certReloader, *tls.Config, error) {
	if f.CertFile == "" || f.KeyFile == "" {
		return nil, nil, errors.New("httpserver: TLS needs both a certificate and a key file")
	}
	r := &certReloader{certFile: f.CertFile, keyFile: f.KeyFile, every: f.CheckEvery, now: f.now}
	if r.every <= 0 {
		r.every = DefaultCertCheck
	}
	if r.now == nil {
		r.now = time.Now
	}
	if err := r.load(); err != nil {
		return nil, nil, err
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: r.get,
		NextProtos:     []string{"h2", "http/1.1"},
	}
	if f.ClientCAFile != "" {
		pem, err := os.ReadFile(f.ClientCAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("httpserver: client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, nil, fmt.Errorf("httpserver: client CA: %s holds no PEM certificate", f.ClientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return r, cfg, nil
}

// certReloader serves the certificate loaded last and reloads it when the
// files' modification times change, looking at most once per interval.
type certReloader struct {
	certFile, keyFile string
	every             time.Duration
	now               func() time.Time

	mu        sync.Mutex
	cert      *tls.Certificate
	certMod   time.Time
	keyMod    time.Time
	checked   time.Time
	lastError error
}

func (r *certReloader) load() error {
	cfi, err := os.Stat(r.certFile)
	if err != nil {
		return fmt.Errorf("httpserver: certificate: %w", err)
	}
	kfi, err := os.Stat(r.keyFile)
	if err != nil {
		return fmt.Errorf("httpserver: key: %w", err)
	}
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("httpserver: %w", err)
	}
	r.cert, r.certMod, r.keyMod, r.checked = &c, cfi.ModTime(), kfi.ModTime(), r.now()
	return nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := r.now(); now.Sub(r.checked) >= r.every {
		r.checked = now
		cfi, cerr := os.Stat(r.certFile)
		kfi, kerr := os.Stat(r.keyFile)
		if cerr == nil && kerr == nil && (!cfi.ModTime().Equal(r.certMod) || !kfi.ModTime().Equal(r.keyMod)) {
			if c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile); err == nil {
				r.cert, r.certMod, r.keyMod, r.lastError = &c, cfi.ModTime(), kfi.ModTime(), nil
			} else {
				// A half-written renewal (new certificate, old key) fails
				// here; the next check after both are written succeeds.
				r.lastError = err
			}
		}
	}
	return r.cert, nil
}

// CertError reports why the last certificate reload failed, or nil when
// the files in use are the newest, or the group serves plain HTTP.
func (g *Group) CertError() error {
	if g.certs == nil {
		return nil
	}
	g.certs.mu.Lock()
	defer g.certs.mu.Unlock()
	return g.certs.lastError
}

// Check loads the files as Listen would, without listening, for a
// subcommand's configuration check.
func (f *TLSFiles) Check() error {
	_, _, err := f.config()
	return err
}
