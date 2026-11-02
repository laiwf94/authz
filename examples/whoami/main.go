// Command whoami is a tiny upstream app for the demo. It shows how an app
// behind the sign-on gateway (authz gateway, formerly wicket) should identify
// users: verify the X-Auth-Token JWT against the gateway's published keys
// instead of trusting the X-Auth-* headers, which anything that can reach the
// app directly could set.
//
//	WHOAMI_ADDR      listen address (default "127.0.0.1:8081")
//	WHOAMI_JWKS_URL  the gateway's key set (default "http://127.0.0.1:4180/.well-known/jwks.json")
//	WHOAMI_ISSUER    expected iss, the gateway's public_url (required)
//	WHOAMI_AUDIENCE  expected aud, the app id in the gateway's config (default "whoami")
//
// Run it next to the gateway:
//
//	authz gateway genkey                    # for WICKET_COOKIE_KEYS
//	WICKET_CONFIG=wicket.json WICKET_COOKIE_KEYS=... authz gateway &
//	WHOAMI_ISSUER=https://app.example.com/_wicket go run ./examples/whoami
//
// wicket/examples/demo.sh puts both behind nginx; docs/proxies.md has the
// proxy configurations.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/laiwf94/authz/internal/authn/jose"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv, nil); err != nil {
		fmt.Fprintln(os.Stderr, "whoami:", err)
		os.Exit(1)
	}
}

// keys fetches the gateway's JWKS and caches it for five minutes.
type keys struct {
	url    string
	client *http.Client

	mu      sync.Mutex
	set     *jose.KeySet
	fetched time.Time
}

func (k *keys) get(ctx context.Context) (*jose.KeySet, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.set != nil && time.Since(k.fetched) < 5*time.Minute {
		return k.set, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, jose.MaxJWKSBytes))
	if err != nil {
		return nil, err
	}
	set, err := jose.ParseKeySet(b)
	if err != nil {
		return nil, err
	}
	k.set, k.fetched = set, time.Now()
	return set, nil
}

func verify(ctx context.Context, k *keys, raw, issuer, audience string) (*jose.Claims, error) {
	tok, err := jose.Parse(raw)
	if err != nil {
		return nil, err
	}
	set, err := k.get(ctx)
	if err != nil {
		return nil, err
	}
	for _, key := range set.Keys {
		if key.ID != tok.Header.Kid {
			continue
		}
		if err := tok.Verify(key, []string{"ES256"}); err != nil {
			return nil, err
		}
		claims, err := jose.ParseClaims(tok.Payload)
		if err != nil {
			return nil, err
		}
		if err := claims.Validate(jose.Expect{Issuer: issuer, Audience: audience, Now: time.Now(), Skew: 30 * time.Second}); err != nil {
			return nil, err
		}
		return claims, nil
	}
	return nil, errors.New("unknown signing key")
}

func run(ctx context.Context, getenv func(string) string, ready func(addr string)) error {
	addr := getenv("WHOAMI_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8081"
	}
	jwksURL := getenv("WHOAMI_JWKS_URL")
	if jwksURL == "" {
		jwksURL = "http://127.0.0.1:4180/.well-known/jwks.json"
	}
	issuer := getenv("WHOAMI_ISSUER")
	if issuer == "" {
		return errors.New("WHOAMI_ISSUER is required (the gateway's public_url)")
	}
	audience := getenv("WHOAMI_AUDIENCE")
	if audience == "" {
		audience = "whoami"
	}
	k := &keys{url: jwksURL, client: &http.Client{Timeout: 5 * time.Second}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		claims, err := verify(r.Context(), k, r.Header.Get("X-Auth-Token"), issuer, audience)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "no valid identity token: " + err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"verified_token": map[string]any{"sub": claims.Subject, "email": claims.String("email"),
				"groups": claims.Raw["groups"], "idp": claims.String("idp"), "aud": claims.Audience, "exp": claims.Expiry},
			"headers": map[string]string{"X-Auth-User": r.Header.Get("X-Auth-User"), "X-Auth-Email": r.Header.Get("X-Auth-Email"),
				"X-Auth-Groups": r.Header.Get("X-Auth-Groups")},
			"path": r.URL.Path,
		})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Printf("whoami listening on %s", ln.Addr())
	if ready != nil {
		ready(ln.Addr().String())
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}
