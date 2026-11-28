package products

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laiwf94/authz/bench/datasets"
)

// Keycloak is the identity provider of the sign-in benchmark, set up
// through its admin REST API: a realm holding the dataset's sign-in
// population (datasets.User) with their groups, and a confidential OpenID
// Connect client for oauth2-proxy whose tokens carry a groups claim, so
// that the groups a provider asserts and the graph's relationships agree.
type Keycloak struct {
	Client *http.Client
	URL    string // base URL, such as http://127.0.0.1:18180
	// AdminUser and AdminPassword sign in to the master realm's admin-cli
	// client (the bootstrap admin of compose.yaml).
	AdminUser, AdminPassword string
	// Realm is the benchmark's realm (default "bench").
	Realm string
	// ClientID (default "bench-proxy") and ClientSecret are the client
	// oauth2-proxy signs in with; RedirectURIs are the addresses a sign-in
	// may return to.
	ClientID, ClientSecret string
	RedirectURIs           []string

	mu      sync.Mutex
	token   string
	expires time.Time
}

// KeycloakBatch is the number of users one partial import carries by
// default: large enough that a request's overhead is small next to the
// password hashing of its users, small enough that one request stays well
// under Keycloak's request timeout.
const KeycloakBatch = 200

func (k *Keycloak) realm() string {
	if k.Realm == "" {
		return "bench"
	}
	return k.Realm
}

func (k *Keycloak) clientID() string {
	if k.ClientID == "" {
		return "bench-proxy"
	}
	return k.ClientID
}

func (k *Keycloak) client() *http.Client {
	if k.Client == nil {
		return http.DefaultClient
	}
	return k.Client
}

// adminToken returns an access token of the admin, signing in again a
// little before the current one expires (admin-cli's last a minute by
// default, less than a large import takes) or when force is set.
func (k *Keycloak) adminToken(ctx context.Context, force bool) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !force && k.token != "" && time.Now().Before(k.expires) {
		return k.token, nil
	}
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {k.AdminUser}, "password": {k.AdminPassword}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(k.URL, "/")+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak admin sign-in: status %d: %s", resp.StatusCode, snippet(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("keycloak admin sign-in: no access token in %s", snippet(body))
	}
	// Sign in again with a quarter of the lifetime left, so that a request
	// sent just before expiry still arrives with a valid token.
	life := time.Duration(out.ExpiresIn) * time.Second
	k.token, k.expires = out.AccessToken, time.Now().Add(life-life/4)
	return k.token, nil
}

func snippet(b []byte) []byte { return bytes.TrimSpace(b[:min(len(b), 512)]) }

// errStatus is an admin API answer that is not the one asked for.
type errStatus struct {
	method, path string
	status       int
	body         []byte
}

func (e *errStatus) Error() string {
	return fmt.Sprintf("keycloak %s %s: status %d: %s", e.method, e.path, e.status, snippet(e.body))
}

// retryable reports whether an answer may succeed when sent again.
func (e *errStatus) retryable() bool {
	return e.status == http.StatusTooManyRequests || e.status >= 500
}

// admin sends one admin API request with the admin's token, signing in
// again once on 401, and decodes an answer with status want into out
// (when out is not nil).
func (k *Keycloak) admin(ctx context.Context, method, path string, body any, want int, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		tok, err := k.adminToken(ctx, attempt > 0)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(k.URL, "/")+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := k.client().Do(req)
		if err != nil {
			return err
		}
		answer, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		if resp.StatusCode != want {
			return &errStatus{method, path, resp.StatusCode, answer}
		}
		if out != nil {
			if err := json.Unmarshal(answer, out); err != nil {
				return fmt.Errorf("keycloak %s %s: %w", method, path, err)
			}
		}
		return nil
	}
}

// clientRepresentation is the client Setup writes: confidential, the
// authorization code flow only, PKCE required, and a groups claim of the
// user's group names in the ID token, the access token and userinfo.
func (k *Keycloak) clientRepresentation() map[string]any {
	return map[string]any{
		"clientId":                  k.clientID(),
		"enabled":                   true,
		"protocol":                  "openid-connect",
		"publicClient":              false,
		"secret":                    k.ClientSecret,
		"standardFlowEnabled":       true,
		"directAccessGrantsEnabled": false,
		"implicitFlowEnabled":       false,
		"redirectUris":              k.RedirectURIs,
		"attributes":                map[string]string{"pkce.code.challenge.method": "S256"},
		"protocolMappers": []map[string]any{{
			"name":           "groups",
			"protocol":       "openid-connect",
			"protocolMapper": "oidc-group-membership-mapper",
			"config": map[string]string{
				"claim.name":           "groups",
				"full.path":            "false",
				"id.token.claim":       "true",
				"access.token.claim":   "true",
				"userinfo.token.claim": "true",
			},
		}},
	}
}

// realmSettings are the realm's settings beyond Keycloak's defaults: the
// realm enabled, with brute-force detection on, as Keycloak's server
// administration guide recommends for production (the benchmark signs in
// only with right passwords, so it never trips).
func (k *Keycloak) realmSettings() map[string]any {
	return map[string]any{"realm": k.realm(), "enabled": true, "bruteForceProtected": true}
}

// Setup creates the realm and the client, or brings an existing realm's
// settings and client back to what the benchmark needs, so running it
// again changes nothing.
func (k *Keycloak) Setup(ctx context.Context) error {
	if k.ClientSecret == "" {
		return errors.New("keycloak: no client secret")
	}
	realm := "/admin/realms/" + url.PathEscape(k.realm())
	err := k.admin(ctx, http.MethodGet, realm, nil, http.StatusOK, nil)
	var es *errStatus
	switch {
	case errors.As(err, &es) && es.status == http.StatusNotFound:
		rep := k.realmSettings()
		rep["clients"] = []map[string]any{k.clientRepresentation()}
		return k.admin(ctx, http.MethodPost, "/admin/realms", rep, http.StatusCreated, nil)
	case err != nil:
		return err
	}
	if err := k.admin(ctx, http.MethodPut, realm, k.realmSettings(), http.StatusNoContent, nil); err != nil {
		return err
	}
	var clients []struct {
		ID string `json:"id"`
	}
	if err := k.admin(ctx, http.MethodGet, realm+"/clients?clientId="+url.QueryEscape(k.clientID()), nil, http.StatusOK, &clients); err != nil {
		return err
	}
	if len(clients) == 0 {
		return k.admin(ctx, http.MethodPost, realm+"/clients", k.clientRepresentation(), http.StatusCreated, nil)
	}
	// The mappers of an existing client are left as they are: a PUT does
	// not replace them, and the groups mapper was written with the client.
	return k.admin(ctx, http.MethodPut, realm+"/clients/"+url.PathEscape(clients[0].ID), k.clientRepresentation(), http.StatusNoContent, nil)
}

// keycloakUser is a datasets.User as Keycloak's user representation. A
// group is named by its graph ID (g12), the value of the groups claim.
func keycloakUser(u datasets.User) map[string]any {
	first, last, _ := strings.Cut(u.Name, " ")
	paths := make([]string, len(u.Groups))
	for i, g := range u.Groups {
		paths[i] = "/" + g
	}
	return map[string]any{
		"username":      u.Username,
		"email":         u.Email,
		"emailVerified": true,
		"firstName":     first,
		"lastName":      last,
		"enabled":       true,
		"groups":        paths,
		"credentials":   []map[string]any{{"type": "password", "value": u.Password, "temporary": false}},
	}
}

// ImportResult is what an import wrote.
type ImportResult struct {
	Users   int64         `json:"users"`
	Groups  int64         `json:"groups"`
	Added   int64         `json:"added"`
	Skipped int64         `json:"skipped"`
	Imports int64         `json:"imports"`
	Retries int64         `json:"retries"`
	Elapsed time.Duration `json:"elapsed_ns"`
}

// ImportUsers writes users 0..n-1 of g's sign-in population into the
// realm with Keycloak's partial import, which hashes each password with the
// realm's policy (Argon2 by default) as a sign-up would. It imports the
// groups the users are in first, in one request, then the users in batches
// of batch (0: KeycloakBatch), workers requests at a time (0: 4). Existing
// groups and users are skipped, so an import can be repeated or resumed. A
// request that fails with 429 or a 5xx status is retried up to five times.
func (k *Keycloak) ImportUsers(ctx context.Context, g datasets.Graph, n, batch, workers int) (res ImportResult, err error) {
	start := time.Now()
	defer func() { res.Elapsed = time.Since(start) }()
	if batch <= 0 {
		batch = KeycloakBatch
	}
	if workers <= 0 {
		workers = 4
	}
	groups := map[string]bool{}
	if err := g.EachUser(n, func(u datasets.User) error {
		for _, x := range u.Groups {
			groups[x] = true
		}
		return nil
	}); err != nil {
		return res, err
	}
	res.Users = int64(n)
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	slices.Sort(names)
	reps := make([]map[string]string, len(names))
	for i, name := range names {
		// A group without its path makes Keycloak 26's partial import fail
		// with a server error.
		reps[i] = map[string]string{"name": name, "path": "/" + name}
	}
	res.Groups = int64(len(names))
	if len(reps) > 0 {
		if err := k.partialImport(ctx, map[string]any{"groups": reps}, &res); err != nil {
			return res, err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan []map[string]any)
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for users := range jobs {
				if err := k.partialImport(ctx, map[string]any{"users": users}, &res); err != nil {
					errOnce.Do(func() { firstErr = err; cancel() })
					return
				}
			}
		}()
	}
	var users []map[string]any
	err = g.EachUser(n, func(u datasets.User) error {
		users = append(users, keycloakUser(u))
		if len(users) < batch {
			return nil
		}
		select {
		case jobs <- users:
			users = nil
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err == nil && len(users) > 0 {
		select {
		case jobs <- users:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return res, firstErr
	}
	return res, err
}

// partialImport posts one partial import that skips what exists, retrying
// an answer that may succeed later, and counts what it added and skipped.
func (k *Keycloak) partialImport(ctx context.Context, body map[string]any, res *ImportResult) error {
	body["ifResourceExists"] = "SKIP"
	path := "/admin/realms/" + url.PathEscape(k.realm()) + "/partialImport"
	backoff := 50 * time.Millisecond
	for attempt := 0; ; attempt++ {
		var out struct {
			Added   int64 `json:"added"`
			Skipped int64 `json:"skipped"`
		}
		err := k.admin(ctx, http.MethodPost, path, body, http.StatusOK, &out)
		if err == nil {
			atomic.AddInt64(&res.Added, out.Added)
			atomic.AddInt64(&res.Skipped, out.Skipped)
			atomic.AddInt64(&res.Imports, 1)
			return nil
		}
		var es *errStatus
		if !errors.As(err, &es) || !es.retryable() || attempt == 5 {
			return err
		}
		atomic.AddInt64(&res.Retries, 1)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff = min(2*backoff, 2*time.Second)
	}
}

// VerifyUsers reads sample users of the first n back from the realm (every
// one when sample is 0 or at least n, else an even spread from u0) and
// fails on the first that is missing, disabled, has another email or is in
// other groups than the graph says.
func (k *Keycloak) VerifyUsers(ctx context.Context, g datasets.Graph, n, sample int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	if sample <= 0 || sample > n {
		sample = n
	}
	realm := "/admin/realms/" + url.PathEscape(k.realm())
	checked := 0
	for i := range sample {
		want := g.User(i * n / sample)
		var found []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Email    string `json:"email"`
			Enabled  bool   `json:"enabled"`
		}
		q := url.Values{"username": {want.Username}, "exact": {"true"}}
		if err := k.admin(ctx, http.MethodGet, realm+"/users?"+q.Encode(), nil, http.StatusOK, &found); err != nil {
			return checked, err
		}
		if len(found) != 1 {
			return checked, fmt.Errorf("keycloak: user %s: found %d accounts", want.Username, len(found))
		}
		if u := found[0]; !u.Enabled || u.Email != want.Email {
			return checked, fmt.Errorf("keycloak: user %s: enabled %t, email %q; want enabled, %q", want.Username, u.Enabled, u.Email, want.Email)
		}
		var groups []struct {
			Name string `json:"name"`
		}
		if err := k.admin(ctx, http.MethodGet, realm+"/users/"+url.PathEscape(found[0].ID)+"/groups", nil, http.StatusOK, &groups); err != nil {
			return checked, err
		}
		got := make([]string, len(groups))
		for j, x := range groups {
			got[j] = x.Name
		}
		wantGroups := slices.Clone(want.Groups)
		slices.Sort(got)
		slices.Sort(wantGroups)
		if !slices.Equal(got, wantGroups) {
			return checked, fmt.Errorf("keycloak: user %s: groups %v, want %v", want.Username, got, wantGroups)
		}
		checked++
	}
	return checked, nil
}
