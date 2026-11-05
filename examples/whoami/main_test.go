package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/jose"
)

func TestWhoami(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jose.NewSigner(k)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{jose.PublicJWK(signer.Public(), signer.KeyID())}})
	}))
	defer jwks.Close()
	now := time.Now().Unix()
	good, _ := signer.Sign(map[string]any{"iss": "https://gw", "aud": "whoami", "sub": "alice", "iat": now, "exp": now + 60, "groups": []string{"eng"}})
	wrongAud, _ := signer.Sign(map[string]any{"iss": "https://gw", "aud": "other", "sub": "alice", "iat": now, "exp": now + 60})

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	env := map[string]string{"WHOAMI_ADDR": "127.0.0.1:0", "WHOAMI_JWKS_URL": jwks.URL, "WHOAMI_ISSUER": "https://gw"}
	k2 := &keys{url: jwks.URL, client: http.DefaultClient}
	if c, err := verify(ctx, k2, good, "https://gw", "whoami"); err != nil || c.Subject != "alice" {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"wrong audience": wrongAud, "garbage": "x.y.z", "empty": ""} {
		if _, err := verify(ctx, k2, tok, "https://gw", "whoami"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSigner, _ := jose.NewSigner(other)
	unknown, _ := otherSigner.Sign(map[string]any{"iss": "https://gw"})
	if _, err := verify(ctx, k2, unknown, "https://gw", "whoami"); err == nil {
		t.Error("unknown key accepted")
	}
	if _, err := (&keys{url: jwks.URL + "/x", client: &http.Client{Transport: errTransport{}}}).get(ctx); err == nil {
		t.Error("transport error")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	if _, err := (&keys{url: bad.URL, client: http.DefaultClient}).get(ctx); err == nil {
		t.Error("500 accepted")
	}
	if err := run(ctx, func(string) string { return "" }, nil); err == nil {
		t.Error("missing issuer accepted")
	}

	go func() { done <- run(ctx, func(k string) string { return env[k] }, func(a string) { ready <- a }) }()
	addr := <-ready
	req, _ := http.NewRequest("GET", "http://"+addr+"/hello", nil)
	req.Header.Set("X-Auth-Token", good)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"sub":"alice"`) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	req, _ = http.NewRequest("GET", "http://"+addr+"/", nil)
	req.Header.Set("X-Auth-User", "admin") // a spoofed header without a token
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Fatal("spoofed header accepted")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type errTransport struct{}

func (errTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF }
