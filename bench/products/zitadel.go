package products

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laiwf94/authz/bench/datasets"
)

// Zitadel is the second identity provider of the sign-in benchmark, set up
// through its management and user APIs with the personal access token of
// the instance's first machine user (compose.yaml writes it to a file).
//
// Zitadel has no groups. A graph group is a role of the benchmark's project
// instead, with the group's ID as its key, and a user's groups are the
// roles of one user grant on that project. The project asserts its roles,
// so the ID token carries them in the RolesClaim claim, an object keyed by
// role. The sign-in client is a web application with PKCE and no secret,
// signing in through the login Zitadel serves itself (login v1), whose
// name input is ZitadelLoginField.
type Zitadel struct {
	Client *http.Client
	URL    string // base URL, such as http://localhost:18280: Zitadel finds the instance by this host
	// Token is the personal access token of an instance administrator.
	Token string
	// Project (default "bench") holds the roles; App (default
	// "bench-login") is the OpenID Connect application users sign in
	// through, returning to one of RedirectURIs.
	Project, App string
	RedirectURIs []string
	// Settle bounds how long a read waits for a write to show (default
	// 30 s): Zitadel's searches and reads answer from projections of its
	// event store, which trail the writes by a moment.
	Settle time.Duration

	// Set by Setup: the organization the token's user belongs to, which
	// holds the project and the users, the project's ID and the
	// application's client ID.
	OrgID, ProjectID, ClientID string
}

// ZitadelLoginField is the name input of login v1's first page.
const ZitadelLoginField = "loginName"

// RolesClaim is the claim of the ID token that holds the roles a user was
// granted on the project the client belongs to.
const RolesClaim = "urn:zitadel:iam:org:project:roles"

func (z *Zitadel) project() string {
	if z.Project == "" {
		return "bench"
	}
	return z.Project
}

func (z *Zitadel) app() string {
	if z.App == "" {
		return "bench-login"
	}
	return z.App
}

func (z *Zitadel) client() *http.Client {
	if z.Client == nil {
		return http.DefaultClient
	}
	return z.Client
}

// zitadelError is an API answer that is not a success.
type zitadelError struct {
	method, path string
	status       int
	body         []byte
}

func (e *zitadelError) Error() string {
	return fmt.Sprintf("zitadel %s %s: status %d: %s", e.method, e.path, e.status, snippet(e.body))
}

func (e *zitadelError) retryable() bool {
	return e.status == http.StatusTooManyRequests || e.status >= 500
}

// exists reports whether err refuses a write because what it writes is
// there already. Zitadel answers that 409 for most resources, and 400
// (failed precondition, Errors.User.AlreadyExisting) for a user ID that is
// taken.
func exists(err error) bool {
	var ze *zitadelError
	return errors.As(err, &ze) && (ze.status == http.StatusConflict ||
		ze.status == http.StatusBadRequest && bytes.Contains(ze.body, []byte(".AlreadyExist")))
}

// api sends one API request with the token and decodes a 2xx answer into
// out (when out is not nil). An answer that may succeed later (429 or a
// 5xx status) is sent again, up to five times, counted in retries.
func (z *Zitadel) api(ctx context.Context, method, path string, body, out any, retries *int64) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	backoff := 50 * time.Millisecond
	for attempt := 0; ; attempt++ {
		err := z.send(ctx, method, path, payload, out)
		var ze *zitadelError
		if err == nil || !errors.As(err, &ze) || !ze.retryable() || attempt == 5 {
			return err
		}
		if retries != nil {
			atomic.AddInt64(retries, 1)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff = min(2*backoff, 2*time.Second)
	}
}

func (z *Zitadel) send(ctx context.Context, method, path string, payload []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(z.URL, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+z.Token)
	resp, err := z.client().Do(req)
	if err != nil {
		return err
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &zitadelError{method, path, resp.StatusCode, answer}
	}
	if out != nil {
		if err := json.Unmarshal(answer, out); err != nil {
			return fmt.Errorf("zitadel %s %s: %w", method, path, err)
		}
	}
	return nil
}

// settle calls fn until it reports done, for up to z.Settle, and returns
// the error of its last call when it never does.
func (z *Zitadel) settle(ctx context.Context, fn func() (bool, error)) error {
	limit := z.Settle
	if limit <= 0 {
		limit = 30 * time.Second
	}
	deadline := time.Now().Add(limit)
	wait := 50 * time.Millisecond
	for {
		done, err := fn()
		if done || time.Now().After(deadline) {
			return err
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
		wait = min(2*wait, time.Second)
	}
}

// zitadelOIDC is the application's OpenID Connect configuration: the
// authorization code flow only, a web application with PKCE and no secret
// (auth method none), roles and userinfo in the ID token, the login Zitadel
// serves itself, and development mode, which allows the benchmark's http
// redirect URIs. The JSON names are the management API's; a value left out
// of an answer is the field's zero value (OIDC_APP_TYPE_WEB,
// OIDC_TOKEN_TYPE_BEARER).
type zitadelOIDC struct {
	RedirectURIs             []string        `json:"redirectUris"`
	ResponseTypes            []string        `json:"responseTypes"`
	GrantTypes               []string        `json:"grantTypes"`
	AppType                  string          `json:"appType,omitempty"`
	AuthMethodType           string          `json:"authMethodType,omitempty"`
	DevMode                  bool            `json:"devMode,omitempty"`
	AccessTokenType          string          `json:"accessTokenType,omitempty"`
	IDTokenRoleAssertion     bool            `json:"idTokenRoleAssertion,omitempty"`
	IDTokenUserinfoAssertion bool            `json:"idTokenUserinfoAssertion,omitempty"`
	LoginVersion             json.RawMessage `json:"loginVersion,omitempty"`
}

func (z *Zitadel) oidcConfig() zitadelOIDC {
	return zitadelOIDC{
		RedirectURIs:             z.RedirectURIs,
		ResponseTypes:            []string{"OIDC_RESPONSE_TYPE_CODE"},
		GrantTypes:               []string{"OIDC_GRANT_TYPE_AUTHORIZATION_CODE"},
		AppType:                  "OIDC_APP_TYPE_WEB",
		AuthMethodType:           "OIDC_AUTH_METHOD_TYPE_NONE",
		DevMode:                  true,
		AccessTokenType:          "OIDC_TOKEN_TYPE_BEARER",
		IDTokenRoleAssertion:     true,
		IDTokenUserinfoAssertion: true,
		LoginVersion:             json.RawMessage(`{"loginV1":{}}`),
	}
}

// same reports whether an application read back has the configuration c.
func (c zitadelOIDC) same(got zitadelOIDC) bool {
	zero := func(v, def string) string {
		if v == "" {
			return def
		}
		return v
	}
	var a, b any
	json.Unmarshal(c.LoginVersion, &a)
	json.Unmarshal(got.LoginVersion, &b)
	return slices.Equal(c.RedirectURIs, got.RedirectURIs) && slices.Equal(c.ResponseTypes, got.ResponseTypes) &&
		slices.Equal(c.GrantTypes, got.GrantTypes) &&
		zero(got.AppType, "OIDC_APP_TYPE_WEB") == c.AppType &&
		zero(got.AuthMethodType, "OIDC_AUTH_METHOD_TYPE_BASIC") == c.AuthMethodType &&
		zero(got.AccessTokenType, "OIDC_TOKEN_TYPE_BEARER") == c.AccessTokenType &&
		got.DevMode == c.DevMode && got.IDTokenRoleAssertion == c.IDTokenRoleAssertion &&
		got.IDTokenUserinfoAssertion == c.IDTokenUserinfoAssertion && fmt.Sprint(a) == fmt.Sprint(b)
}

type zitadelProject struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	ProjectRoleAssertion bool   `json:"projectRoleAssertion"`
}

type zitadelApp struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	OIDCConfig *struct {
		zitadelOIDC
		ClientID string `json:"clientId"`
	} `json:"oidcConfig"`
}

// Setup finds the token's organization, creates the project and the
// application, or brings existing ones back to the benchmark's settings,
// and sets OrgID, ProjectID and ClientID. Running it again changes
// nothing.
func (z *Zitadel) Setup(ctx context.Context) error {
	if len(z.RedirectURIs) == 0 {
		return errors.New("zitadel: no redirect URIs")
	}
	var me struct {
		Org struct {
			ID string `json:"id"`
		} `json:"org"`
	}
	if err := z.api(ctx, http.MethodGet, "/management/v1/orgs/me", nil, &me, nil); err != nil {
		return err
	}
	if me.Org.ID == "" {
		return errors.New("zitadel: the token's user is in no organization")
	}
	z.OrgID = me.Org.ID
	p, err := z.ensureProject(ctx)
	if err != nil {
		return err
	}
	z.ProjectID = p
	z.ClientID, err = z.ensureApp(ctx)
	return err
}

func nameQuery(field, name string) map[string]any {
	return map[string]any{"queries": []map[string]any{{field: map[string]string{"name": name, "method": "TEXT_QUERY_METHOD_EQUALS"}}}}
}

func (z *Zitadel) ensureProject(ctx context.Context) (string, error) {
	find := func() (*zitadelProject, error) {
		var out struct {
			Result []zitadelProject `json:"result"`
		}
		if err := z.api(ctx, http.MethodPost, "/management/v1/projects/_search", nameQuery("nameQuery", z.project()), &out, nil); err != nil {
			return nil, err
		}
		for _, p := range out.Result {
			if p.Name == z.project() {
				return &p, nil
			}
		}
		return nil, nil
	}
	p, err := find()
	if err != nil {
		return "", err
	}
	want := map[string]any{"name": z.project(), "projectRoleAssertion": true}
	if p == nil {
		var out struct {
			ID string `json:"id"`
		}
		err := z.api(ctx, http.MethodPost, "/management/v1/projects", want, &out, nil)
		if err == nil {
			return out.ID, nil
		}
		if !exists(err) {
			return "", err
		}
		// Created a moment ago, by an earlier run, and not yet searchable.
		if err := z.settle(ctx, func() (bool, error) {
			var err error
			p, err = find()
			return p != nil || err != nil, err
		}); err != nil {
			return "", err
		}
		if p == nil {
			return "", fmt.Errorf("zitadel: project %q exists but cannot be found", z.project())
		}
	}
	if !p.ProjectRoleAssertion {
		if err := z.api(ctx, http.MethodPut, "/management/v1/projects/"+url.PathEscape(p.ID), want, nil, nil); err != nil {
			return "", err
		}
	}
	return p.ID, nil
}

func (z *Zitadel) ensureApp(ctx context.Context) (string, error) {
	apps := "/management/v1/projects/" + url.PathEscape(z.ProjectID) + "/apps"
	find := func() (*zitadelApp, error) {
		var out struct {
			Result []zitadelApp `json:"result"`
		}
		if err := z.api(ctx, http.MethodPost, apps+"/_search", nameQuery("nameQuery", z.app()), &out, nil); err != nil {
			return nil, err
		}
		for _, a := range out.Result {
			if a.Name == z.app() {
				if a.OIDCConfig == nil {
					return nil, fmt.Errorf("zitadel: application %q is not an OpenID Connect application", a.Name)
				}
				return &a, nil
			}
		}
		return nil, nil
	}
	a, err := find()
	if err != nil {
		return "", err
	}
	want := z.oidcConfig()
	if a == nil {
		body := map[string]any{"name": z.app()}
		b, _ := json.Marshal(want)
		var fields map[string]any
		json.Unmarshal(b, &fields)
		maps.Copy(body, fields)
		var out struct {
			ClientID string `json:"clientId"`
		}
		err := z.api(ctx, http.MethodPost, apps+"/oidc", body, &out, nil)
		if err == nil {
			if out.ClientID == "" {
				return "", errors.New("zitadel: the new application has no client ID")
			}
			return out.ClientID, nil
		}
		if !exists(err) {
			return "", err
		}
		if err := z.settle(ctx, func() (bool, error) {
			var err error
			a, err = find()
			return a != nil || err != nil, err
		}); err != nil {
			return "", err
		}
		if a == nil {
			return "", fmt.Errorf("zitadel: application %q exists but cannot be found", z.app())
		}
	}
	if !want.same(a.OIDCConfig.zitadelOIDC) {
		// An update that changes nothing is refused, so only a differing
		// configuration is written.
		if err := z.api(ctx, http.MethodPut, apps+"/"+url.PathEscape(a.ID)+"/oidc_config", want, nil, nil); err != nil {
			return "", err
		}
	}
	return a.OIDCConfig.ClientID, nil
}

// roles returns the keys of the project's roles.
func (z *Zitadel) roles(ctx context.Context) (map[string]bool, error) {
	keys := map[string]bool{}
	const page = 500
	for offset := 0; ; offset += page {
		var out struct {
			Result []struct {
				Key string `json:"key"`
			} `json:"result"`
		}
		body := map[string]any{"query": map[string]any{"offset": offset, "limit": page, "asc": true}}
		if err := z.api(ctx, http.MethodPost, "/management/v1/projects/"+url.PathEscape(z.ProjectID)+"/roles/_search", body, &out, nil); err != nil {
			return nil, err
		}
		for _, r := range out.Result {
			keys[r.Key] = true
		}
		if len(out.Result) < page {
			return keys, nil
		}
	}
}

// zitadelUser is a datasets.User as the user API's new human: its ID and
// user name are the graph's (u12), with a verified email and a password
// that need not be changed.
func (z *Zitadel) zitadelUser(u datasets.User) map[string]any {
	first, last, _ := strings.Cut(u.Name, " ")
	return map[string]any{
		"userId":       u.Username,
		"username":     u.Username,
		"organization": map[string]string{"orgId": z.OrgID},
		"profile":      map[string]string{"givenName": first, "familyName": last, "displayName": u.Name},
		"email":        map[string]any{"email": u.Email, "isVerified": true},
		"password":     map[string]any{"password": u.Password, "changeRequired": false},
	}
}

// ImportUsers writes users 0..n-1 of g's sign-in population into the
// organization, after Setup: first a role for each group the users are in,
// then each user with a user grant of its groups' roles, workers users at a
// time (0: 8). Zitadel imports one user per request and hashes its password
// as a sign-up would. What exists is skipped, so an import can be repeated
// or resumed: a user counts as added when the user or its grant was
// written. Each role and each user is one import in res.Imports.
func (z *Zitadel) ImportUsers(ctx context.Context, g datasets.Graph, n, workers int) (res ImportResult, err error) {
	start := time.Now()
	defer func() { res.Elapsed = time.Since(start) }()
	if z.ProjectID == "" || z.OrgID == "" {
		return res, errors.New("zitadel: import before setup")
	}
	if workers <= 0 {
		workers = 8
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
	res.Users, res.Groups = int64(n), int64(len(groups))
	have, err := z.roles(ctx)
	if err != nil {
		return res, err
	}
	roles := "/management/v1/projects/" + url.PathEscape(z.ProjectID) + "/roles"
	for _, key := range slices.Sorted(maps.Keys(groups)) {
		if have[key] {
			res.Skipped++
			continue
		}
		res.Imports++
		err := z.api(ctx, http.MethodPost, roles, map[string]string{"roleKey": key, "displayName": key}, nil, &res.Retries)
		switch {
		case err == nil:
			res.Added++
		case exists(err):
			res.Skipped++
		default:
			return res, err
		}
	}
	// A grant names roles, which must be readable first.
	if err := z.settle(ctx, func() (bool, error) {
		have, err := z.roles(ctx)
		for key := range groups {
			if !have[key] {
				return err != nil, cmpOr(err, fmt.Errorf("zitadel: role %s was added but is not listed", key))
			}
		}
		return true, err
	}); err != nil {
		return res, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan datasets.User)
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				if err := z.importUser(ctx, u, &res); err != nil {
					errOnce.Do(func() { firstErr = err; cancel() })
					return
				}
			}
		}()
	}
	err = g.EachUser(n, func(u datasets.User) error {
		select {
		case jobs <- u:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return res, firstErr
	}
	return res, err
}

func cmpOr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

func (z *Zitadel) importUser(ctx context.Context, u datasets.User, res *ImportResult) error {
	atomic.AddInt64(&res.Imports, 1)
	wrote := false
	err := z.api(ctx, http.MethodPost, "/v2/users/human", z.zitadelUser(u), nil, &res.Retries)
	switch {
	case err == nil:
		wrote = true
	case !exists(err):
		return err
	}
	if len(u.Groups) > 0 {
		grant := map[string]any{"projectId": z.ProjectID, "roleKeys": u.Groups}
		err = z.api(ctx, http.MethodPost, "/management/v1/users/"+url.PathEscape(u.Username)+"/grants", grant, nil, &res.Retries)
		switch {
		case err == nil:
			wrote = true
		case !exists(err):
			return err
		}
	}
	if wrote {
		atomic.AddInt64(&res.Added, 1)
	} else {
		atomic.AddInt64(&res.Skipped, 1)
	}
	return nil
}

// grantedRoles returns the roles of a user's grants on the project.
func (z *Zitadel) grantedRoles(ctx context.Context, user string) ([]string, error) {
	var out struct {
		Result []struct {
			RoleKeys []string `json:"roleKeys"`
		} `json:"result"`
	}
	body := map[string]any{"queries": []map[string]any{
		{"userIdQuery": map[string]string{"userId": user}},
		{"projectIdQuery": map[string]string{"projectId": z.ProjectID}},
	}}
	if err := z.api(ctx, http.MethodPost, "/management/v1/users/grants/_search", body, &out, nil); err != nil {
		return nil, err
	}
	var roles []string
	for _, g := range out.Result {
		roles = append(roles, g.RoleKeys...)
	}
	slices.Sort(roles)
	return slices.Compact(roles), nil
}

// verifyUser reads one user back and returns an error when it is missing,
// not active, has another email or other roles than the graph's groups.
func (z *Zitadel) verifyUser(ctx context.Context, want datasets.User) error {
	var out struct {
		User struct {
			UserID   string `json:"userId"`
			Username string `json:"username"`
			State    string `json:"state"`
			Human    *struct {
				Email struct {
					Email      string `json:"email"`
					IsVerified bool   `json:"isVerified"`
				} `json:"email"`
				PasswordChangeRequired bool `json:"passwordChangeRequired"`
			} `json:"human"`
		} `json:"user"`
	}
	if err := z.api(ctx, http.MethodGet, "/v2/users/"+url.PathEscape(want.Username), nil, &out, nil); err != nil {
		return err
	}
	u := out.User
	if u.Username != want.Username || u.State != "USER_STATE_ACTIVE" || u.Human == nil || u.Human.Email.Email != want.Email ||
		!u.Human.Email.IsVerified || u.Human.PasswordChangeRequired {
		return fmt.Errorf("zitadel: user %s: %+v; want an active human %s with the verified email %s and no password change", want.Username, u, want.Username, want.Email)
	}
	got, err := z.grantedRoles(ctx, want.Username)
	if err != nil {
		return err
	}
	groups := slices.Sorted(slices.Values(want.Groups))
	if !slices.Equal(got, groups) {
		return fmt.Errorf("zitadel: user %s: roles %v, want the groups %v", want.Username, got, groups)
	}
	return nil
}

// VerifyUsers reads sample users of the first n back (every one when sample
// is 0 or at least n, else an even spread from u0) and fails on the first
// that is missing, not active, has another email or other roles than the
// graph's groups. A user that does not match yet is read again for a
// while, since reads trail writes.
func (z *Zitadel) VerifyUsers(ctx context.Context, g datasets.Graph, n, sample int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	if sample <= 0 || sample > n {
		sample = n
	}
	for i := range sample {
		want := g.User(i * n / sample)
		if err := z.settle(ctx, func() (bool, error) {
			err := z.verifyUser(ctx, want)
			var ze *zitadelError
			if errors.As(err, &ze) && ze.status != http.StatusNotFound {
				return true, err // refused, not late
			}
			return err == nil, err
		}); err != nil {
			return i, err
		}
	}
	return sample, nil
}

// SignInResult is what a sign-in through the application proved: the ID
// token's subject, email and the roles in its RolesClaim.
type SignInResult struct {
	Subject, Email string
	Roles          []string
}

// Browser signs a user in from start as a browser does, filling the
// provider's forms, and returns the redirect to an address starting with
// done that ended the sign-in (ops.Browser makes one).
type Browser func(ctx context.Context, start, done, user, password string) (*url.URL, error)

// SignIn signs u in through the application with browser, with the
// authorization code flow and PKCE, redeems the code with client and
// returns what the ID token says. It fails when the ID token is not for the
// application or the issuer.
func (z *Zitadel) SignIn(ctx context.Context, client *http.Client, browser Browser, u datasets.User) (SignInResult, error) {
	var res SignInResult
	if z.ClientID == "" {
		return res, errors.New("zitadel: sign-in before setup")
	}
	verifier := make([]byte, 32)
	rand.Read(verifier)
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifier)
	sum := sha256.Sum256([]byte(codeVerifier))
	base := strings.TrimSuffix(z.URL, "/")
	redirect := z.RedirectURIs[0]
	q := url.Values{"client_id": {z.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {"openid email profile"}, "state": {"bench"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	done, err := browser(ctx, base+"/oauth/v2/authorize?"+q.Encode(), redirect, u.Username, u.Password)
	if err != nil {
		return res, err
	}
	if s := done.Query().Get("state"); s != "bench" {
		return res, fmt.Errorf("zitadel: sign-in of %s returned state %q", u.Username, s)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {done.Query().Get("code")}, "redirect_uri": {redirect},
		"client_id": {z.ClientID}, "code_verifier": {codeVerifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/oauth/v2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return res, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return res, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return res, err
	}
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("zitadel: redeeming the code of %s: status %d: %s", u.Username, resp.StatusCode, snippet(body))
	}
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil || tokens.IDToken == "" {
		return res, fmt.Errorf("zitadel: no ID token for %s in %s", u.Username, snippet(body))
	}
	parts := strings.Split(tokens.IDToken, ".")
	if len(parts) != 3 {
		return res, fmt.Errorf("zitadel: the ID token of %s is not a JWT", u.Username)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return res, fmt.Errorf("zitadel: the ID token of %s: %w", u.Username, err)
	}
	var claims struct {
		Issuer  string                     `json:"iss"`
		Subject string                     `json:"sub"`
		Email   string                     `json:"email"`
		Aud     audience                   `json:"aud"`
		Roles   map[string]json.RawMessage `json:"urn:zitadel:iam:org:project:roles"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return res, fmt.Errorf("zitadel: the ID token of %s: %w", u.Username, err)
	}
	if claims.Issuer != base || !slices.Contains(claims.Aud, z.ClientID) {
		return res, fmt.Errorf("zitadel: the ID token of %s is from %q for %v, want %q for %s", u.Username, claims.Issuer, claims.Aud, base, z.ClientID)
	}
	res.Subject, res.Email = claims.Subject, claims.Email
	res.Roles = slices.Sorted(maps.Keys(claims.Roles))
	return res, nil
}

// audience is a JWT's aud claim, which is a string or a list of them.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	return json.Unmarshal(b, (*[]string)(a))
}
