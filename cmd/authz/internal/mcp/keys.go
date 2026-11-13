package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/laiwf94/authz/cmd/authz/internal/part"
	"github.com/laiwf94/authz/internal/agents/gateway"
	"github.com/laiwf94/authz/internal/platform/keys"
)

// DefaultSigningPolicy is how the agent ring of a keys_file rotates unless
// signing_rotate_every and signing_overlap say otherwise: a new signing key
// every day, the old one verifying for a day after, far longer than the
// longest token an agents config may allow (tokens.max_ttl_seconds, at
// most 24h, 1h by default).
var DefaultSigningPolicy = keys.Policy{RotateEvery: 24 * time.Hour, Overlap: 24 * time.Hour}

func agentSpec(p keys.Policy) keys.Spec {
	return keys.Spec{Name: keys.RingAgent, Alg: keys.HS256, Policy: p}
}

// signingKeyList is the signing keys as ring keys, the active one first and
// the others by key id, keeping toolgate's key ids so tokens they signed
// still name a key the ring holds.
func signingKeyList(m map[string][]byte, active string, now time.Time) ([]*keys.Key, error) {
	if len(m) == 0 {
		return nil, nil
	}
	kids := make([]string, 0, len(m))
	for kid := range m {
		if kid != active {
			kids = append(kids, kid)
		}
	}
	slices.Sort(kids)
	kids = append([]string{active}, kids...)
	out := make([]*keys.Key, 0, len(kids))
	for _, kid := range kids {
		k, err := keys.FromSecret(keys.HS256, kid, m[kid], now)
		if err != nil {
			return nil, fmt.Errorf("signing key %s: %s", kid, policyError(err))
		}
		out = append(out, k)
	}
	return out, nil
}

// configuredRing is the agent ring of a gateway with no keys_file: the
// signing keys as a configured ring that never rotates on its own, the
// active key signing and every key verifying, as toolgate's key list did.
// It is nil when no signing keys are set: static keys only.
func configuredRing(c config, now time.Time) (*keys.Ring, error) {
	ks, err := signingKeyList(c.keys, c.activeKey, now)
	if err != nil || len(ks) == 0 {
		return nil, err
	}
	return keys.Configured(keys.Policy{}, now, ks...)
}

// agentRing is the ring agent tokens are signed and verified with: the
// agent ring of the keys_file, or the configured signing keys. fk is nil
// without a keys_file.
func agentRing(h part.Host, c config, gc *gateway.Config, now time.Time, log *slog.Logger, fromFile bool) (*keys.Ring, *fileKeys, error) {
	if c.keysFile == "" {
		r, err := configuredRing(c, now)
		return r, nil, err
	}
	if gc.Tokens == nil {
		return nil, nil, errors.New("config: a keys file is set but the config has no tokens section, which signed agent tokens need")
	}
	fk, err := openFileKeys(h, c, now, log, fromFile)
	if err != nil {
		return nil, nil, err
	}
	for _, w := range keyPolicyWarnings(c.signingPol, gc.MaxTokenTTL()) {
		log.Warn("key rotation: "+w, "keys_file", c.keysFile)
	}
	return fk.ring, fk, nil
}

// fileKeys is the agent ring of a keys_file.
type fileKeys struct {
	file *keys.File
	ring *keys.Ring
}

// openFileKeys puts agent tokens on the agent ring of the process's ring
// file, adding it when the file lacks it. A ring that is added starts from
// the signing keys when they are set, so tokens they signed keep
// verifying; once the file holds the ring, the signing keys are ignored.
func openFileKeys(h part.Host, c config, now time.Time, log *slog.Logger, fromFile bool) (*fileKeys, error) {
	kf, err := h.KeyFile(c.keysFile)
	if err != nil {
		return nil, fmt.Errorf("keys file: %w", err)
	}
	sp := agentSpec(c.signingPol)
	if sp.Seed, err = signingKeyList(c.keys, c.activeKey, now); err != nil {
		return nil, err
	}
	member := legacyPrefix + "SIGNING_KEYS"
	if fromFile {
		member = "signing_keys"
	}
	switch held := kf.Set().Ring(sp.Name) != nil; {
	case held && len(sp.Seed) > 0:
		log.Warn("the keys file already holds this ring; "+member+" is ignored and can be removed",
			"keys_file", c.keysFile, "ring", sp.Name)
	case !held && len(sp.Seed) > 0:
		log.Info("starting the ring from "+member, "keys_file", c.keysFile, "ring", sp.Name, "keys", len(sp.Seed))
	}
	rings, err := kf.Ensure(sp)
	if err != nil {
		return nil, fmt.Errorf("keys file: %w", err)
	}
	return &fileKeys{file: kf, ring: rings[0]}, nil
}

// start rotates the file's rings until ctx ends and logs the agent ring's
// rotations and failed checks. The channel is closed once the rotations
// this start asked for have stopped. The authenticator reads the ring on
// every token, so a rotation needs nothing else.
func (fk *fileKeys) start(ctx context.Context, path string, log *slog.Logger) <-chan struct{} {
	remove := fk.file.OnChange(func(changed []string, err error) {
		if err != nil {
			log.Error("key ring check failed; the rings keep their keys", "keys_file", path, "error", err.Error())
		}
		if slices.Contains(changed, keys.RingAgent) {
			log.Info("key ring rotated", "keys_file", path, "ring", keys.RingAgent, "signing_kid", fk.ring.Current().ID())
		}
	})
	context.AfterFunc(ctx, remove)
	return fk.file.Start(ctx)
}

// keyPolicyWarnings are the problems of rotation settings that work but
// may refuse tokens: a token signed just before a rotation lives up to
// maxTTL, and is refused once its key's overlap ends.
func keyPolicyWarnings(p keys.Policy, maxTTL time.Duration) []string {
	if p.RotateEvery > 0 && p.Overlap < maxTTL {
		return []string{fmt.Sprintf("signing_overlap %s is shorter than the agents config's longest token lifetime %s: "+
			"tokens signed just before a rotation are refused once their key's overlap ends", p.Overlap, maxTTL)}
	}
	return nil
}

func policyError(err error) string { return strings.TrimPrefix(err.Error(), "keys: ") }

// parsePolicy reads a rotation period and overlap given as durations, such
// as "24h"; "0" or "0s" never rotates. Empty keeps def's value.
func parsePolicy(every, overlap string, def keys.Policy) (keys.Policy, error) {
	p := def
	for _, f := range []struct {
		v string
		d *time.Duration
	}{{every, &p.RotateEvery}, {overlap, &p.Overlap}} {
		if f.v == "" {
			continue
		}
		d, err := time.ParseDuration(f.v)
		if f.v == "0" {
			d, err = 0, nil
		}
		if err != nil || d < 0 {
			return p, fmt.Errorf("%q is not a duration such as 24h", f.v)
		}
		*f.d = d
	}
	return p, p.Check()
}
