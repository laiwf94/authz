package mcp

import (
	"context"
	"crypto/x509"
	"log/slog"
	"slices"
	"sync"

	"github.com/laiwf94/authz/internal/agents/gateway"
	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/platform/keys"
)

// jwksPool holds the JWKS clients of the configured issuers while authz
// mcp serve runs. Each client refreshes its key set on schedule until it
// is no longer used or the server shuts down. Issuers with the same
// jwks_uri, private networks and CA certificates share one client, and a
// reload keeps a client, with the keys it holds, while those are
// unchanged, so a reload neither refetches nor drops keys.
type jwksPool struct {
	ctx context.Context // the clients' lifetime
	log *slog.Logger

	mu      sync.Mutex
	clients map[string]*pooledJWKS // by IssuerConfig.JWKSKey
	wg      sync.WaitGroup
}

type pooledJWKS struct {
	jwks    *identity.JWKS
	url     string
	issuers []string
	stop    context.CancelFunc // nil until started
}

func newJWKSPool(ctx context.Context, log *slog.Logger) *jwksPool {
	return &jwksPool{ctx: ctx, log: log, clients: map[string]*pooledJWKS{}}
}

// pending is an authenticator built on the pool and the clients it
// needs. Nothing changes in the pool until commit.
type pending struct {
	auth *identity.Authenticator
	next map[string]*pooledJWKS
}

// authenticator builds the authenticator for gc on ring (nil for none)
// with its issuers' keys from the pool: running clients where their key
// is unchanged, new ones otherwise. cas holds CA files the check read.
func (p *jwksPool) authenticator(gc *gateway.Config, ring *keys.Ring, cas map[string][]byte) (*pending, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := map[string]*pooledJWKS{}
	keysFor := func(ic gateway.IssuerConfig) (identity.KeySource, error) {
		ca, pem, err := readIssuerCA(ic, cas)
		if err != nil {
			return nil, err
		}
		key := ic.JWKSKey(pem)
		e := next[key]
		if e == nil {
			if e = p.clients[key]; e == nil {
				j, err := ic.NewJWKS(ca, p.log)
				if err != nil {
					return nil, err
				}
				e = &pooledJWKS{jwks: j, url: ic.JWKSURI}
			}
			next[key] = e
		}
		return e.jwks, nil
	}
	auth, err := gc.NewIssuerAuthenticator(ring, keysFor)
	if err != nil {
		return nil, err
	}
	// The issuers each client serves, for the log.
	issuers := map[string][]string{}
	for _, ic := range gc.Issuers {
		_, pem, _ := readIssuerCA(ic, cas)
		k := ic.JWKSKey(pem)
		issuers[k] = append(issuers[k], ic.Issuer)
	}
	for k, e := range next {
		if e.stop == nil {
			e.issuers = issuers[k]
		}
	}
	return &pending{auth: auth, next: next}, nil
}

// readIssuerCA returns an issuer's CA certificates: the bytes the
// configuration check read, when it read them, or the file's.
func readIssuerCA(ic gateway.IssuerConfig, cas map[string][]byte) (ca *x509.CertPool, pem []byte, err error) {
	if ic.CAFile == "" {
		return nil, nil, nil
	}
	if b, ok := cas[ic.CAFile]; ok {
		pool, err := gateway.ParseCA(b)
		if err != nil {
			return nil, nil, err
		}
		return pool, b, nil
	}
	pool, b, err := ic.ReadCA()
	if err != nil {
		return nil, nil, err
	}
	return pool, b, nil
}

// commit puts pd's clients in force once its authenticator is: new
// clients start refreshing, and those it no longer uses stop.
func (p *jwksPool) commit(pd *pending) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range pd.next {
		if e.stop != nil {
			continue
		}
		ctx, stop := context.WithCancel(p.ctx)
		e.stop = stop
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			e.jwks.Run(ctx)
		}()
		p.log.Info("jwks client started", "jwks_uri", e.url, "issuers", e.issuers)
	}
	for k, e := range p.clients {
		if _, ok := pd.next[k]; !ok {
			e.stop()
			p.log.Info("jwks client stopped", "jwks_uri", e.url)
		}
	}
	p.clients = pd.next
}

// same reports whether gc's issuers would use exactly the running
// clients: nothing to rebuild for them.
func (p *jwksPool) same(gc *gateway.Config, cas map[string][]byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	want := map[string]bool{}
	for _, ic := range gc.Issuers {
		_, pem, err := readIssuerCA(ic, cas)
		if err != nil {
			return false
		}
		want[ic.JWKSKey(pem)] = true
	}
	if len(want) != len(p.clients) {
		return false
	}
	for k := range want {
		if _, ok := p.clients[k]; !ok {
			return false
		}
	}
	return true
}

// urls lists the running clients' jwks_uri values, sorted.
func (p *jwksPool) urls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, e := range p.clients {
		out = append(out, e.url)
	}
	slices.Sort(out)
	return out
}

// close stops every client and waits for their refresh loops to end.
func (p *jwksPool) close() {
	p.mu.Lock()
	for _, e := range p.clients {
		if e.stop != nil {
			e.stop()
		}
	}
	p.mu.Unlock()
	p.wg.Wait()
}
