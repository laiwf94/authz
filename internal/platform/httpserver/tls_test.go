package httpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: k, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns a PEM certificate and key for a server (127.0.0.1) or a
// client, with the serial given.
func (ca *testCA) issue(t *testing.T, serial int64, client bool) (certPEM, keyPEM []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	if client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

func writeFile(t *testing.T, path string, b []byte, mod time.Time) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func handshake(t *testing.T, addr string, cfg *tls.Config) (*tls.ConnectionState, error) {
	t.Helper()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	st := c.ConnectionState()
	return &st, nil
}

func TestTLS(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t)
	cert, key := ca.issue(t, 10, false)
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	writeFile(t, certFile, cert, t0)
	writeFile(t, keyFile, key, t0)
	clock := &fakeClock{t: time.Now()}

	g, err := Listen(Options{TLS: &TLSFiles{CertFile: certFile, KeyFile: keyFile, CheckEvery: time.Minute, now: clock.now}},
		Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok), ReadyPath: "/readyz"},
		Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)})
	if err != nil {
		t.Fatal(err)
	}
	serveGroup(t, g)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: true}}

	for _, addr := range g.Addrs() {
		resp, err := client.Get("https://" + addr + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 || resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
			t.Errorf("%s: proto %s, tls %+v", addr, resp.Proto, resp.TLS)
		}
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d %s", addr, resp.StatusCode, b)
		}
	}
	// Plain HTTP and TLS 1.1 are refused.
	if resp, err := http.Get("http://" + g.Addrs()[0] + "/"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("plain HTTP to a TLS listener: %d", resp.StatusCode)
		}
	}
	if _, err := handshake(t, g.Addrs()[0], &tls.Config{RootCAs: roots, MaxVersion: tls.VersionTLS11}); err == nil {
		t.Error("TLS 1.1 handshake succeeded")
	}

	serial := func() int64 {
		t.Helper()
		st, err := handshake(t, g.Addrs()[0], &tls.Config{RootCAs: roots})
		if err != nil {
			t.Fatal(err)
		}
		return st.PeerCertificates[0].SerialNumber.Int64()
	}
	if s := serial(); s != 10 {
		t.Fatalf("serial %d", s)
	}

	// A renewal is picked up at the next check, not before.
	cert2, key2 := ca.issue(t, 11, false)
	writeFile(t, certFile, cert2, t0.Add(time.Minute))
	writeFile(t, keyFile, key2, t0.Add(time.Minute))
	if s := serial(); s != 10 {
		t.Errorf("reloaded before the check interval: serial %d", s)
	}
	clock.add(time.Minute)
	if s := serial(); s != 11 {
		t.Errorf("renewal not picked up: serial %d", s)
	}
	if err := g.CertError(); err != nil {
		t.Errorf("CertError: %v", err)
	}

	// A half-written renewal keeps the certificate in use and says why.
	cert3, _ := ca.issue(t, 12, false)
	writeFile(t, certFile, cert3, t0.Add(2*time.Minute))
	clock.add(time.Minute)
	if s := serial(); s != 11 {
		t.Errorf("mismatched renewal: serial %d", s)
	}
	if err := g.CertError(); err == nil {
		t.Error("CertError nil after a failed reload")
	}
	// Then the key lands and the next check loads both.
	cert4, key4 := ca.issue(t, 14, false)
	writeFile(t, certFile, cert4, t0.Add(3*time.Minute))
	writeFile(t, keyFile, key4, t0.Add(3*time.Minute))
	clock.add(time.Minute)
	if s := serial(); s != 14 {
		t.Errorf("renewal after a failure: serial %d", s)
	}
	if err := g.CertError(); err != nil {
		t.Errorf("CertError after recovery: %v", err)
	}
}

func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t)
	cert, key := ca.issue(t, 20, false)
	ccert, ckey := ca.issue(t, 21, true)
	files := map[string][]byte{"tls.crt": cert, "tls.key": key, "ca.crt": ca.pem}
	for n, b := range files {
		writeFile(t, filepath.Join(dir, n), b, time.Now())
	}
	g, err := Listen(Options{TLS: &TLSFiles{CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key"),
		ClientCAFile: filepath.Join(dir, "ca.crt")}}, Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)})
	if err != nil {
		t.Fatal(err)
	}
	serveGroup(t, g)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	get := func(certs []tls.Certificate) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certs}}}
		resp, err := c.Get("https://" + g.Addrs()[0] + "/")
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(nil); err == nil {
		t.Error("request without a client certificate succeeded")
	}
	other := newCA(t)
	ocert, okey := other.issue(t, 22, true)
	oc, _ := tls.X509KeyPair(ocert, okey)
	if err := get([]tls.Certificate{oc}); err == nil {
		t.Error("request with a certificate from another CA succeeded")
	}
	cc, err := tls.X509KeyPair(ccert, ckey)
	if err != nil {
		t.Fatal(err)
	}
	if err := get([]tls.Certificate{cc}); err != nil {
		t.Errorf("request with a client certificate: %v", err)
	}
}

func TestTLSFileErrors(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t)
	cert, key := ca.issue(t, 30, false)
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeFile(t, certFile, cert, time.Now())
	writeFile(t, keyFile, key, time.Now())
	notPEM := filepath.Join(dir, "junk")
	writeFile(t, notPEM, []byte("not pem"), time.Now())
	missing := filepath.Join(dir, "missing")
	for name, f := range map[string]TLSFiles{
		"certificate":     {CertFile: missing, KeyFile: keyFile},
		"key":             {CertFile: certFile, KeyFile: missing},
		"tls: ":           {CertFile: certFile, KeyFile: notPEM},
		"client CA: open": {CertFile: certFile, KeyFile: keyFile, ClientCAFile: missing},
		"no PEM":          {CertFile: certFile, KeyFile: keyFile, ClientCAFile: notPEM},
	} {
		_, err := Listen(Options{TLS: &f}, Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)})
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := (&Group{}).CertError(); err != nil {
		t.Errorf("plain group CertError: %v", err)
	}
}
