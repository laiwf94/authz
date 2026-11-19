package gateway

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/agents/httpx"
	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/keys"
)

// Static agent keys on the admin API. The key set is the configured keys
// (token_sha256 of each agent) merged with the keys the admin API issued
// and the revocations it recorded, kept in the static key file
// (keys.StaticStore). Every change names the key set version it was made
// against, from GET /admin/keys or the last change's answer, and fails
// with 409 when another change came first. A change is saved before it
// takes effect and is audited; the secret of a new key is in the answer
// only, never stored, logged or audited.
//
//	GET  /admin/keys                       the key set and its version
//	POST /admin/keys                       {"agent", "version"}: issue a key
//	POST /admin/keys/{id}/rotate           {"version", "overlap_seconds"}: replace a key
//	POST /admin/keys/{id}/revoke           {"version"}: revoke a key at once

// staticKeyView is a key as the admin API shows it.
type staticKeyView struct {
	ID      string `json:"id"`
	Agent   string `json:"agent"`
	Source  string `json:"source"`
	Created string `json:"created,omitempty"`
	Until   string `json:"until,omitempty"`
}

func viewKey(k keys.StaticKey) staticKeyView {
	v := staticKeyView{ID: k.ID, Agent: k.Agent, Source: k.Source}
	if !k.Created.IsZero() {
		v.Created = k.Created.UTC().Format(time.RFC3339)
	}
	if !k.Until.IsZero() {
		v.Until = k.Until.UTC().Format(time.RFC3339)
	}
	return v
}

// configKeys are the static keys c lists.
func configKeys(c *Config) []keys.ConfigKey {
	out := make([]keys.ConfigKey, 0, len(c.Agents))
	for _, a := range c.identityAgents() {
		out = append(out, keys.ConfigKey{Agent: a.ID, SHA256: a.TokenSHA256})
	}
	return out
}

// staticAt is the static key store read at the gateway's clock, which set
// the end of every overlap.
type staticAt struct {
	s   *keys.StaticStore
	now func() time.Time
}

func (x staticAt) Issued(sum [32]byte) (string, string, bool) { return x.s.Issued(sum, x.now()) }
func (x staticAt) ConfigActive(sum [32]byte) bool             { return x.s.ConfigActive(sum, x.now()) }

// StaticKeys returns the static key store the gateway checks static keys
// against and the admin API changes.
func (g *Gateway) StaticKeys() *keys.StaticStore { return g.static }

func setVersion(w http.ResponseWriter, v uint64) {
	w.Header().Set("ETag", `"`+strconv.FormatUint(v, 10)+`"`)
	w.Header().Set("Cache-Control", "no-store")
}

func (g *Gateway) listStaticKeys(w http.ResponseWriter, r *http.Request) error {
	set := g.agents.Load()
	v, list := g.static.List(set.configKeys, g.now())
	out := make([]staticKeyView, len(list))
	for i, k := range list {
		out[i] = viewKey(k)
	}
	setVersion(w, v)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"version": v, "keys": out})
	return nil
}

// keyChange is the body of a change.
type keyChange struct {
	Agent          string  `json:"agent"`
	Version        *uint64 `json:"version"`
	OverlapSeconds int64   `json:"overlap_seconds"`
}

func (g *Gateway) decodeChange(w http.ResponseWriter, r *http.Request) (keyChange, error) {
	var b keyChange
	if err := httpx.DecodeJSON(w, r, adminBodyLimit, &b); err != nil {
		return b, err
	}
	if b.Version == nil {
		return b, httpx.BadRequest("version is required: the key set version from GET /admin/keys")
	}
	return b, nil
}

// changeError maps a store error to its answer.
func (g *Gateway) changeError(w http.ResponseWriter, err error) error {
	switch {
	case errors.Is(err, keys.ErrVersion):
		setVersion(w, g.static.Version())
		return &httpx.Error{Status: http.StatusConflict, Code: "version_conflict",
			Msg: strings.TrimPrefix(err.Error(), "keys: ") + "; read the key set again"}
	case errors.Is(err, keys.ErrNotFound):
		return &httpx.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no static key with that id verifies now"}
	case errors.Is(err, keys.ErrStaticLimit):
		return &httpx.Error{Status: http.StatusConflict, Code: "resource_exhausted", Msg: strings.TrimPrefix(err.Error(), "keys: ")}
	case errors.Is(err, keys.ErrConflict):
		g.log.Error("static key file changed under the gateway; the change was not made", "error", err.Error())
		return &httpx.Error{Status: http.StatusConflict, Code: "failed_precondition",
			Msg: "the static key file was changed by another process; the change was not made"}
	}
	return err
}

// newSecret makes a static key whose digest the key set doesn't hold.
func newSecret() (string, [32]byte) {
	t := identity.NewStaticToken()
	return t, identity.HashToken(t)
}

func (g *Gateway) createStaticKey(w http.ResponseWriter, r *http.Request) error {
	b, err := g.decodeChange(w, r)
	if err != nil {
		return err
	}
	if b.OverlapSeconds != 0 {
		return httpx.BadRequest("overlap_seconds applies only to rotations")
	}
	set := g.agents.Load()
	if !slices.ContainsFunc(set.configKeys, func(c keys.ConfigKey) bool { return c.Agent == b.Agent }) {
		return httpx.BadRequest("agent %q is not in the agents configuration", b.Agent)
	}
	secret, sum := newSecret()
	k, v, err := g.static.Create(*b.Version, set.configKeys, b.Agent, sum, g.now())
	if err != nil {
		return g.changeError(w, err)
	}
	if err := g.audit(r.Context(), audit.EventStaticKeyCreated, map[string]any{"agent": k.Agent, "key_id": k.ID, "version": v}); err != nil {
		return err
	}
	g.log.InfoContext(r.Context(), "static key issued", "agent", k.Agent, "key_id", k.ID, "version", v)
	setVersion(w, v)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"version": v, "key": viewKey(k), "secret": secret})
	return nil
}

func (g *Gateway) rotateStaticKey(w http.ResponseWriter, r *http.Request) error {
	b, err := g.decodeChange(w, r)
	if err != nil {
		return err
	}
	if b.Agent != "" {
		return httpx.BadRequest("a rotated key keeps its agent; leave agent out")
	}
	if b.OverlapSeconds < 0 || b.OverlapSeconds > int64(keys.MaxStaticOverlap/time.Second) {
		return httpx.BadRequest("overlap_seconds must be from 0 to %d", int64(keys.MaxStaticOverlap/time.Second))
	}
	set := g.agents.Load()
	secret, sum := newSecret()
	old, k, v, err := g.static.Rotate(*b.Version, set.configKeys, r.PathValue("id"), sum,
		time.Duration(b.OverlapSeconds)*time.Second, g.now())
	if err != nil {
		return g.changeError(w, err)
	}
	if err := g.audit(r.Context(), audit.EventStaticKeyRotated, map[string]any{"agent": k.Agent, "key_id": old.ID,
		"source": old.Source, "new_key_id": k.ID, "until": old.Until.UTC().Format(time.RFC3339), "version": v}); err != nil {
		return err
	}
	g.log.InfoContext(r.Context(), "static key rotated", "agent", k.Agent, "key_id", old.ID, "new_key_id", k.ID,
		"until", old.Until.UTC().Format(time.RFC3339), "version", v)
	setVersion(w, v)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"version": v, "old": viewKey(old), "key": viewKey(k), "secret": secret})
	return nil
}

func (g *Gateway) revokeStaticKey(w http.ResponseWriter, r *http.Request) error {
	b, err := g.decodeChange(w, r)
	if err != nil {
		return err
	}
	if b.Agent != "" || b.OverlapSeconds != 0 {
		return httpx.BadRequest("a revocation takes only version")
	}
	set := g.agents.Load()
	k, v, err := g.static.Revoke(*b.Version, set.configKeys, r.PathValue("id"), g.now())
	if err != nil {
		return g.changeError(w, err)
	}
	if err := g.audit(r.Context(), audit.EventStaticKeyRevoked, map[string]any{"agent": k.Agent, "key_id": k.ID,
		"source": k.Source, "version": v}); err != nil {
		return err
	}
	g.log.InfoContext(r.Context(), "static key revoked", "agent", k.Agent, "key_id", k.ID, "source", k.Source, "version", v)
	setVersion(w, v)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"version": v, "key": viewKey(k)})
	return nil
}
