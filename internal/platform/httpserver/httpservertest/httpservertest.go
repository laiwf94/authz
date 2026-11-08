// Package httpservertest writes throwaway TLS files for tests of the
// subcommands that serve through internal/platform/httpserver.
package httpservertest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Files are a server certificate for 127.0.0.1 and its key, written to a
// test's temporary directory, and an HTTPS client that trusts it.
type Files struct {
	CertFile, KeyFile string
	Client            *http.Client
}

// Write creates the files; they are removed with the test.
func Write(t testing.TB) Files {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := Files{CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key")}
	if err := os.WriteFile(f.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}
	t.Cleanup(tr.CloseIdleConnections)
	f.Client = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	return f
}
