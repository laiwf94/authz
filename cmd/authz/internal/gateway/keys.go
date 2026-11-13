package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/laiwf94/authz/cmd/authz/internal/part"
	"github.com/laiwf94/authz/internal/authn/server"
	"github.com/laiwf94/authz/internal/platform/keys"
	"github.com/laiwf94/authz/internal/platform/seal"
)

// DefaultCookiePolicy is how the session ring of a keys_file rotates unless
// cookie_rotate_every and cookie_overlap say otherwise: a new cookie key
// every day, the old one opening cookies for two days, which covers
// wicket's default absolute session lifetime of 24h.
var DefaultCookiePolicy = keys.Policy{RotateEvery: 24 * time.Hour, Overlap: 48 * time.Hour}

// DefaultSigningPolicy is how the upstream ring of a keys_file rotates
// unless signing_rotate_every and signing_overlap say otherwise: a new
// signing key every day, published a day before it signs and for a day
// after, far longer than an upstream token lives or an upstream caches the
// JWKS (5 minutes).
var DefaultSigningPolicy = keys.Policy{RotateEvery: 24 * time.Hour, Overlap: 24 * time.Hour}

// jwksMaxAge is the Cache-Control max-age of /.well-known/jwks.json. A ring
// that rotates faster may sign with a key an upstream's cached set lacks.
const jwksMaxAge = 5 * time.Minute

func cookieSpec(p keys.Policy) keys.Spec {
	return keys.Spec{Name: keys.RingSession, Alg: keys.A256GCM, Policy: p}
}

func signingSpec(p keys.Policy) keys.Spec {
	return keys.Spec{Name: keys.RingUpstream, Alg: keys.ES256, Policy: p}
}

// signingKeys reads the signing_keys PEM files, first one signing.
func signingKeys(files []string, now time.Time) ([]*keys.Key, error) {
	ecs, err := loadECKeys(files)
	if err != nil {
		return nil, err
	}
	out := make([]*keys.Key, 0, len(ecs))
	for i, k := range ecs {
		kk, err := keys.FromSigner(k, now)
		if err != nil {
			return nil, fmt.Errorf("signing key %s: %w", files[i], err)
		}
		if slices.ContainsFunc(out, func(o *keys.Key) bool { return o.ID() == kk.ID() }) {
			return nil, fmt.Errorf("signing key %s: the same key is listed twice", files[i])
		}
		out = append(out, kk)
	}
	return out, nil
}

// configuredUpstream is the upstream ring of a gateway with no keys_file:
// the signing_keys as a configured ring that never rotates on its own, or
// one key generated for this process.
func configuredUpstream(st settings, now time.Time, log *slog.Logger, fromFile bool) (*keys.Ring, error) {
	ks, err := signingKeys(st.signingKeys, now)
	if err != nil {
		return nil, err
	}
	if len(ks) == 0 {
		if fromFile {
			log.Warn("$.gateway.signing_keys not set; using a key generated for this process, so upstream tokens can't be verified across replicas or restarts")
		} else {
			log.Warn("WICKET_SIGNING_KEYS not set; using a key generated for this process, so upstream tokens can't be verified across replicas or restarts")
		}
		k, err := keys.Generate(keys.ES256, now)
		if err != nil {
			return nil, err
		}
		ks = []*keys.Key{k}
	}
	return keys.Configured(keys.Policy{}, now, ks...)
}

// fileKeys is the gateway's keys on the rings of a keys_file.
type fileKeys struct {
	file     *keys.File
	cookies  *seal.Keyring
	upstream *keys.Ring
}

// openFileKeys puts session cookies on the session ring and upstream
// tokens on the upstream ring of the process's ring file, adding the rings
// the file lacks. A ring that is added starts from cookie_keys or
// signing_keys when they are set, so cookies and tokens issued before the
// move keep working; once the file holds the ring, the lists are ignored.
func openFileKeys(h part.Host, st settings, now func() time.Time, log *slog.Logger) (*fileKeys, error) {
	kf, err := h.KeyFile(st.keysFile)
	if err != nil {
		return nil, fmt.Errorf("keys file: %w", err)
	}
	t := now()
	cs, us := cookieSpec(st.cookiePol), signingSpec(st.signingPol)
	for _, ck := range st.cookieKeys {
		k, err := keys.FromSecret(keys.A256GCM, "", ck, t)
		if err != nil {
			return nil, fmt.Errorf("cookie key: %w", err)
		}
		cs.Seed = append(cs.Seed, k)
	}
	if us.Seed, err = signingKeys(st.signingKeys, t); err != nil {
		return nil, err
	}
	for _, sp := range []keys.Spec{cs, us} {
		member := map[string]string{keys.RingSession: "cookie_keys", keys.RingUpstream: "signing_keys"}[sp.Name]
		switch held := kf.Set().Ring(sp.Name) != nil; {
		case held && len(sp.Seed) > 0:
			log.Warn("the keys file already holds this ring; "+member+" is ignored and can be removed",
				"keys_file", st.keysFile, "ring", sp.Name)
		case !held && len(sp.Seed) > 0:
			log.Info("starting the ring from "+member, "keys_file", st.keysFile, "ring", sp.Name, "keys", len(sp.Seed))
		}
	}
	rings, err := kf.Ensure(cs, us)
	if err != nil {
		return nil, fmt.Errorf("keys file: %w", err)
	}
	cookies, err := seal.FromRing(rings[0], now)
	if err != nil {
		return nil, err
	}
	return &fileKeys{file: kf, cookies: cookies, upstream: rings[1]}, nil
}

// start rotates the rings until ctx ends, refreshing the server's
// published JWKS after every change to the upstream ring, and logs
// rotations and failed checks. The channel is closed once the rotations
// this start asked for have stopped.
func (fk *fileKeys) start(ctx context.Context, srv *server.Server, path string, log *slog.Logger) <-chan struct{} {
	remove := fk.file.OnChange(func(changed []string, err error) {
		if err != nil {
			log.Error("key ring check failed; the rings keep their keys", "keys_file", path, "error", err.Error())
		}
		for _, name := range changed {
			switch name {
			case keys.RingUpstream:
				if err := srv.RefreshKeys(); err != nil {
					log.Error("refreshing the published keys failed", "keys_file", path, "error", err.Error())
					continue
				}
				log.Info("key ring rotated", "keys_file", path, "ring", name, "signing_kid", fk.upstream.Current().ID())
			case keys.RingSession:
				log.Info("key ring rotated", "keys_file", path, "ring", name)
			}
		}
	})
	context.AfterFunc(ctx, remove)
	// Another part of the process may have rotated the file since the
	// server was built.
	_ = srv.RefreshKeys()
	return fk.file.Start(ctx)
}

// keyPolicyWarnings are the problems of rotation settings that work but
// may log people out or fail token checks.
func keyPolicyWarnings(cookie, signing keys.Policy, absolute, tokenTTL time.Duration) []string {
	var out []string
	if cookie.RotateEvery > 0 && cookie.Overlap < absolute {
		out = append(out, fmt.Sprintf("cookie_overlap %s is shorter than the session's absolute timeout %s: "+
			"sessions older than the overlap are signed out when their cookie key retires", cookie.Overlap, absolute))
	}
	if signing.RotateEvery > 0 && signing.Overlap < tokenTTL {
		out = append(out, fmt.Sprintf("signing_overlap %s is shorter than upstream_token_ttl %s: "+
			"upstreams refuse tokens issued just before a rotation once their key is no longer published", signing.Overlap, tokenTTL))
	}
	if signing.RotateEvery > 0 && signing.RotateEvery < jwksMaxAge {
		out = append(out, fmt.Sprintf("signing_rotate_every %s is shorter than the %s upstreams may cache the JWKS for: "+
			"they may see tokens signed by a key their cached set lacks", signing.RotateEvery, jwksMaxAge))
	}
	return out
}

func policyError(err error) string { return strings.TrimPrefix(err.Error(), "keys: ") }
