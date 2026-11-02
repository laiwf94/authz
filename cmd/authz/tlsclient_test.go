package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"testing"
)

// tlsClient trusts only the CA in caFile.
func tlsClient(t *testing.T, caFile string) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("no CA certificate in " + caFile)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
}
