package httpservertest

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrite(t *testing.T) {
	f := Write(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})}
	go s.ServeTLS(ln, f.CertFile, f.KeyFile)
	defer s.Close()
	resp, err := f.Client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.ProtoMajor != 2 {
		t.Errorf("%d over %s", resp.StatusCode, resp.Proto)
	}

	// The client trusts only the written certificate.
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer other.Close()
	if resp, err := f.Client.Get(other.URL); err == nil {
		resp.Body.Close()
		t.Error("client trusted a certificate it was not given")
	}
}
