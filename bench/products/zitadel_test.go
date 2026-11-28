package products

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/bench/datasets"
	"github.com/laiwf94/authz/bench/ops"
	"github.com/laiwf94/authz/bench/products/productstest"
)

const zitadelRedirect = "http://127.0.0.1:18089/callback"

func newZitadel(t *testing.T, lag int) (*productstest.Zitadel, *Zitadel) {
	t.Helper()
	fake := &productstest.Zitadel{Token: "admin-pat", Lag: lag}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return fake, &Zitadel{Client: srv.Client(), URL: srv.URL, Token: "admin-pat", RedirectURIs: []string{zitadelRedirect},
		Settle: 2 * time.Second}
}

// Setup creates the project and the application, finds them again when
// they exist, and puts back a setting that was changed.
func TestZitadelSetup(t *testing.T) {
	ctx := context.Background()
	fake, z := newZitadel(t, 2)
	if err := z.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	p := fake.Project("bench")
	if p == nil || !p.ProjectRoleAssertion || len(p.Apps) != 1 || z.OrgID != productstest.ZitadelOrgID || z.ProjectID != p.ID {
		t.Fatalf("project %+v, setup %+v", p, z)
	}
	a := p.Apps[0]
	if a.Name != "bench-login" || z.ClientID != a.ClientID || a.Config["authMethodType"] != "OIDC_AUTH_METHOD_TYPE_NONE" ||
		a.Config["devMode"] != true || a.Config["idTokenRoleAssertion"] != true || a.Config["idTokenUserinfoAssertion"] != true {
		t.Fatalf("app %+v", a)
	}
	if lv, _ := a.Config["loginVersion"].(map[string]any); lv == nil || lv["loginV1"] == nil {
		t.Errorf("login version %v", a.Config["loginVersion"])
	}
	// Again right away: the project and app are not searchable yet, so
	// creating them is refused and Setup waits until they show.
	again := &Zitadel{Client: z.Client, URL: z.URL, Token: z.Token, RedirectURIs: z.RedirectURIs, Settle: time.Second}
	if err := again.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	if again.ClientID != z.ClientID || again.ProjectID != z.ProjectID || len(fake.Project("bench").Apps) != 1 || p.Updates != 0 || a.Updates != 0 {
		t.Fatalf("setup again: %+v, %d updates of the project, %d of the app", again, p.Updates, a.Updates)
	}
	// Settings changed by hand are put back; nothing else is written.
	p.ProjectRoleAssertion = false
	delete(a.Config, "devMode")
	if err := again.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	if !p.ProjectRoleAssertion || a.Config["devMode"] != true || p.Updates != 1 || a.Updates != 1 {
		t.Fatalf("after repair: %+v %+v", p, a)
	}
	// Other redirect URIs are a changed configuration.
	again.RedirectURIs = []string{zitadelRedirect, "http://127.0.0.1:18089/other"}
	if err := again.Setup(ctx); err != nil || a.Updates != 2 {
		t.Fatalf("new redirect URIs: %v, %d updates", err, a.Updates)
	}
}

func TestZitadelSetupErrors(t *testing.T) {
	ctx := context.Background()
	fake, z := newZitadel(t, 0)
	if err := (&Zitadel{URL: z.URL, Token: "x"}).Setup(ctx); err == nil || !strings.Contains(err.Error(), "no redirect URIs") {
		t.Errorf("no redirect URIs: %v", err)
	}
	bad := *z
	bad.Token = "wrong"
	if err := bad.Setup(ctx); err == nil || !strings.Contains(err.Error(), "status 401") {
		t.Errorf("wrong token: %v", err)
	}
	for _, path := range []string{"/management/v1/projects/_search", "/management/v1/projects", "/apps/_search", "/apps/oidc"} {
		fake.SetFail(func(r *http.Request) int {
			if strings.HasSuffix(r.URL.Path, path) {
				return http.StatusForbidden
			}
			return 0
		})
		if err := z.Setup(ctx); err == nil || !strings.Contains(err.Error(), "status 403") {
			t.Errorf("refused %s: %v", path, err)
		}
	}
	// A server error is retried.
	var fails atomic.Int64
	fake.SetFail(func(r *http.Request) int {
		if strings.HasSuffix(r.URL.Path, "/orgs/me") && fails.Add(1) <= 2 {
			return http.StatusServiceUnavailable
		}
		return 0
	})
	if err := z.Setup(ctx); err != nil || fails.Load() != 3 {
		t.Errorf("retried setup: %v after %d tries", err, fails.Load())
	}
	fake.SetFail(nil)
	if _, err := (&Zitadel{}).ImportUsers(ctx, datasets.Graph{}, 0, 0); err == nil {
		t.Error("import before setup")
	}
	if _, err := (&Zitadel{}).SignIn(ctx, http.DefaultClient, nil, datasets.User{}); err == nil {
		t.Error("sign-in before setup")
	}
}

func TestZitadelImportUsers(t *testing.T) {
	ctx := context.Background()
	fake, z := newZitadel(t, 3)
	if err := z.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	g, err := datasets.Size(100_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	const n = 150
	res, err := z.ImportUsers(ctx, g, n, 4)
	if err != nil {
		t.Fatal(err)
	}
	if fake.Users() != n {
		t.Fatalf("%d users imported, want %d", fake.Users(), n)
	}
	groups := map[string]bool{}
	for i := range n {
		want := g.User(i)
		got := fake.User(want.Username)
		if got == nil {
			t.Fatalf("%s missing", want.Username)
		}
		wantGroups := slices.Sorted(slices.Values(want.Groups))
		for _, x := range wantGroups {
			groups[x] = true
		}
		gotGroups := slices.Sorted(slices.Values(got.Grants[z.ProjectID]))
		if got.Password != want.Password || got.Email != want.Email || !got.EmailVerified || got.PasswordChangeRequired ||
			got.Username != want.Username || got.GivenName != "Bench" || got.FamilyName != "User "+strings.TrimPrefix(want.Username, "u") ||
			!slices.Equal(gotGroups, wantGroups) {
			t.Fatalf("%s: got %+v, want %+v", want.Username, got, want)
		}
	}
	p := fake.Project("bench")
	if len(p.Roles) != len(groups) || res.Groups != int64(len(groups)) {
		t.Errorf("%d roles, %d imported; the users are in %d groups", len(p.Roles), res.Groups, len(groups))
	}
	if res.Users != n || res.Added != int64(n+len(groups)) || res.Skipped != 0 || res.Imports != int64(n+len(groups)) || res.Retries != 0 {
		t.Errorf("first import: %+v", res)
	}
	checked, err := z.VerifyUsers(ctx, g, n, 0)
	if err != nil || checked != n {
		t.Fatalf("verify: %d %v", checked, err)
	}
	again, err := z.ImportUsers(ctx, g, n, 0)
	if err != nil || again.Added != 0 || again.Skipped != int64(n+len(groups)) || again.Imports != n {
		t.Errorf("second import: %+v %v", again, err)
	}
	// A user whose grant is missing (an import cut short) gets it.
	delete(fake.User("u7").Grants, z.ProjectID)
	again, err = z.ImportUsers(ctx, g, n, 2)
	if err != nil || again.Added != 1 || fake.User("u7").Grants[z.ProjectID] == nil {
		t.Errorf("resumed import: %+v %v", again, err)
	}
	if checked, err := z.VerifyUsers(ctx, g, n, 10); err != nil || checked != 10 {
		t.Errorf("sampled verify: %d %v", checked, err)
	}
	if checked, err := z.VerifyUsers(ctx, g, 0, 10); err != nil || checked != 0 {
		t.Errorf("verify of none: %d %v", checked, err)
	}

	// What does not match fails once reads had time to catch up.
	z.Settle = 200 * time.Millisecond
	u := fake.User("u3")
	u.Grants[z.ProjectID] = []string{"g0"}
	if _, err := z.VerifyUsers(ctx, g, 5, 0); err == nil || !strings.Contains(err.Error(), "u3: roles [g0]") {
		t.Errorf("other roles: %v", err)
	}
	u.Grants[z.ProjectID] = slices.Clone(g.User(3).Groups)
	u.Email = "other@bench.example"
	if _, err := z.VerifyUsers(ctx, g, 5, 0); err == nil || !strings.Contains(err.Error(), "verified email") {
		t.Errorf("other email: %v", err)
	}
	u.Email = g.User(3).Email
	if _, err := z.VerifyUsers(ctx, g, n+1, 0); err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Errorf("missing user: %v", err)
	}
	fake.SetFail(func(r *http.Request) int {
		if strings.HasPrefix(r.URL.Path, "/v2/users/") && r.Method == http.MethodGet {
			return http.StatusForbidden
		}
		return 0
	})
	if _, err := z.VerifyUsers(ctx, g, 5, 0); err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Errorf("refused read: %v", err)
	}
	for _, path := range []string{"/roles/_search", "/v2/users/human", "/grants"} {
		fake.SetFail(func(r *http.Request) int {
			if strings.HasSuffix(r.URL.Path, path) && r.Method == http.MethodPost {
				return http.StatusBadRequest
			}
			return 0
		})
		if _, err := z.ImportUsers(ctx, g, n+20, 3); err == nil || !strings.Contains(err.Error(), "status 400") {
			t.Errorf("refused %s: %v", path, err)
		}
	}
	fake.SetFail(nil)

	// A role that cannot be added stops the import before any user.
	fresh, z2 := newZitadel(t, 0)
	if err := z2.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	fresh.SetFail(func(r *http.Request) int {
		if strings.HasSuffix(r.URL.Path, "/roles") {
			return http.StatusBadRequest
		}
		return 0
	})
	if _, err := z2.ImportUsers(ctx, g, 5, 0); err == nil || !strings.Contains(err.Error(), "status 400") || fresh.Users() != 0 {
		t.Errorf("refused role: %v, %d users", err, fresh.Users())
	}
	// A role that was added but never shows stops it too.
	z2.Settle = 100 * time.Millisecond
	fresh.SetFail(nil)
	fresh.SetLag(1 << 30)
	if _, err := z2.ImportUsers(ctx, g, 5, 0); err == nil || !strings.Contains(err.Error(), "is not listed") {
		t.Errorf("role never listed: %v", err)
	}
}

// A user signs in through login v1 and the ID token carries the user's
// groups as the project's roles.
func TestZitadelSignIn(t *testing.T) {
	ctx := context.Background()
	fake, z := newZitadel(t, 0)
	if err := z.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	g, _ := datasets.Size(100_000, 1)
	if _, err := z.ImportUsers(ctx, g, 20, 0); err != nil {
		t.Fatal(err)
	}
	client, err := ops.NewClient(2, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		u := g.User(i)
		res, err := z.SignIn(ctx, client, ops.Browser(client, ZitadelLoginField), u)
		if err != nil {
			t.Fatal(err)
		}
		if res.Subject != u.Username || res.Email != u.Email || !slices.Equal(res.Roles, slices.Sorted(slices.Values(u.Groups))) {
			t.Errorf("%s: %+v, want groups %v", u.Username, res, u.Groups)
		}
	}
	if fake.SignIns != 3 {
		t.Errorf("%d codes redeemed", fake.SignIns)
	}
	wrong := g.User(4)
	wrong.Password = "pw-wrong-password"
	if _, err := z.SignIn(ctx, client, ops.Browser(client, ZitadelLoginField), wrong); err == nil || !strings.Contains(err.Error(), "was refused") {
		t.Errorf("wrong password: %v", err)
	}
	// An ID token from another issuer is refused.
	fake.Issuer = "http://elsewhere.example"
	if _, err := z.SignIn(ctx, client, ops.Browser(client, ZitadelLoginField), g.User(1)); err == nil || !strings.Contains(err.Error(), `from "http://elsewhere.example"`) {
		t.Errorf("other issuer: %v", err)
	}
	fake.Issuer = ""
	fake.SetFail(func(r *http.Request) int {
		if r.URL.Path == "/oauth/v2/token" {
			return http.StatusBadRequest
		}
		return 0
	})
	if _, err := z.SignIn(ctx, client, ops.Browser(client, ZitadelLoginField), g.User(1)); err == nil || !strings.Contains(err.Error(), "redeeming the code") {
		t.Errorf("refused code: %v", err)
	}
	fake.SetFail(nil)
}

func TestAudience(t *testing.T) {
	var a audience
	if err := a.UnmarshalJSON([]byte(`"one"`)); err != nil || !slices.Equal(a, audience{"one"}) {
		t.Errorf("%v %v", a, err)
	}
	if err := a.UnmarshalJSON([]byte(`["a","b"]`)); err != nil || !slices.Equal(a, audience{"a", "b"}) {
		t.Errorf("%v %v", a, err)
	}
	if err := a.UnmarshalJSON([]byte(`3`)); err == nil {
		t.Error("a number")
	}
}

// Setup's refusals: an update refused, a name that exists but never shows
// in searches, and an application of the name that is not OpenID Connect.
func TestZitadelSetupRefused(t *testing.T) {
	ctx := context.Background()
	fake, z := newZitadel(t, 0)
	if err := z.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	p := fake.Project("bench")
	p.ProjectRoleAssertion = false
	delete(p.Apps[0].Config, "devMode")
	fake.SetFail(func(r *http.Request) int {
		if r.Method == http.MethodPut {
			return http.StatusForbidden
		}
		return 0
	})
	if err := z.Setup(ctx); err == nil || !strings.Contains(err.Error(), "PUT /management/v1/projects/") {
		t.Errorf("refused project update: %v", err)
	}
	p.ProjectRoleAssertion = true
	if err := z.Setup(ctx); err == nil || !strings.Contains(err.Error(), "/oidc_config: status 403") {
		t.Errorf("refused app update: %v", err)
	}
	fake.SetFail(nil)

	// Created a moment ago and never searchable here.
	_, z2 := newZitadel(t, 1<<30)
	z2.Settle = 100 * time.Millisecond
	if err := z2.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := z2.Setup(ctx); err == nil || !strings.Contains(err.Error(), `project "bench" exists but cannot be found`) {
		t.Errorf("hidden project: %v", err)
	}

	// A search that answers an application without an OIDC configuration.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/orgs/me"):
			w.Write([]byte(`{"org":{"id":"1"}}`))
		case strings.HasSuffix(r.URL.Path, "/projects/_search"):
			w.Write([]byte(`{"result":[{"id":"p1","name":"bench","projectRoleAssertion":true}]}`))
		case strings.HasSuffix(r.URL.Path, "/apps/_search"):
			w.Write([]byte(`{"result":[{"id":"a1","name":"bench-login","apiConfig":{}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	api := &Zitadel{URL: srv.URL, Token: "t", RedirectURIs: []string{zitadelRedirect}}
	if err := api.Setup(ctx); err == nil || !strings.Contains(err.Error(), "not an OpenID Connect application") {
		t.Errorf("API application: %v", err)
	}
	noOrg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer noOrg.Close()
	if err := (&Zitadel{URL: noOrg.URL, Token: "t", RedirectURIs: []string{zitadelRedirect}}).Setup(ctx); err == nil ||
		!strings.Contains(err.Error(), "in no organization") {
		t.Errorf("no organization: %v", err)
	}
	notJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`<html>`)) }))
	defer notJSON.Close()
	if err := (&Zitadel{URL: notJSON.URL, Token: "t", RedirectURIs: []string{zitadelRedirect}}).Setup(ctx); err == nil {
		t.Error("an answer that is not JSON")
	}
	if err := (&Zitadel{URL: "http://127.0.0.1:1", Token: "t", RedirectURIs: []string{zitadelRedirect}}).Setup(ctx); err == nil {
		t.Error("a closed port")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	busy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer busy.Close()
	if err := (&Zitadel{URL: busy.URL, Token: "t", RedirectURIs: []string{zitadelRedirect}}).Setup(cancelled); err == nil {
		t.Error("a cancelled retry")
	}
}

// What SignIn refuses in the answers after the browser's part.
func TestZitadelSignInAnswers(t *testing.T) {
	ctx := context.Background()
	var token string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(token))
	}))
	defer srv.Close()
	z := &Zitadel{URL: srv.URL, ClientID: "c1", RedirectURIs: []string{zitadelRedirect}}
	browse := func(q string) Browser {
		return func(ctx context.Context, start, done, user, password string) (*url.URL, error) {
			return url.Parse(done + "?" + q)
		}
	}
	jwt := func(claims string) string {
		return `{"id_token":"eyJhbGciOiJSUzI1NiJ9.` + base64.RawURLEncoding.EncodeToString([]byte(claims)) + `.c2ln"}`
	}
	u := datasets.User{Username: "u1"}
	for _, c := range []struct{ query, token, want string }{
		{"code=x&state=other", "", `returned state "other"`},
		{"code=x&state=bench", `{}`, "no ID token"},
		{"code=x&state=bench", `{"id_token":"a.b"}`, "not a JWT"},
		{"code=x&state=bench", `{"id_token":"a.!!.c"}`, "illegal base64"},
		{"code=x&state=bench", jwt(`[]`), "cannot unmarshal"},
		{"code=x&state=bench", jwt(`{"iss":"` + srv.URL + `","aud":"other"}`), "for [other]"},
		{"code=x&state=bench", jwt(`{"iss":"` + srv.URL + `","aud":["c1"],"sub":"u1"}`), ""},
	} {
		token = c.token
		res, err := z.SignIn(ctx, srv.Client(), browse(c.query), u)
		if c.want == "" {
			if err != nil || res.Subject != "u1" || len(res.Roles) != 0 {
				t.Errorf("%s: %+v %v", c.token, res, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s: %v, want %q", c.query, c.token, err, c.want)
		}
	}
	failing := func(ctx context.Context, start, done, user, password string) (*url.URL, error) {
		return nil, errors.New("browser failed")
	}
	if _, err := z.SignIn(ctx, srv.Client(), failing, u); err == nil || err.Error() != "browser failed" {
		t.Errorf("browser: %v", err)
	}
	closed := &Zitadel{URL: "http://127.0.0.1:1", ClientID: "c1", RedirectURIs: []string{zitadelRedirect}}
	if _, err := closed.SignIn(ctx, http.DefaultClient, browse("code=x&state=bench"), u); err == nil {
		t.Error("token endpoint on a closed port")
	}
}
