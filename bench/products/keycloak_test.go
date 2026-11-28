package products

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/laiwf94/authz/bench/datasets"
	"github.com/laiwf94/authz/bench/products/productstest"
)

func newKeycloak(t *testing.T) (*productstest.Keycloak, *Keycloak) {
	t.Helper()
	fake := &productstest.Keycloak{AdminUser: "bench-admin", AdminPassword: "admin-pass"}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return fake, &Keycloak{Client: srv.Client(), URL: srv.URL, AdminUser: "bench-admin", AdminPassword: "admin-pass",
		ClientSecret: "client-secret", RedirectURIs: []string{"http://127.0.0.1:14180/oauth2/callback"}}
}

// Setup creates the realm with the client oauth2-proxy needs, and running
// it again leaves one realm and one client, mappers kept.
func TestKeycloakSetup(t *testing.T) {
	ctx := context.Background()
	fake, kc := newKeycloak(t)
	if err := kc.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	realm := fake.Realm("bench")
	if realm == nil || realm.Settings["bruteForceProtected"] != true || realm.Settings["enabled"] != true {
		t.Fatalf("realm %+v", realm)
	}
	check := func(want int) {
		t.Helper()
		realm := fake.Realm("bench")
		if len(realm.Clients) != want {
			t.Fatalf("%d clients, want %d", len(realm.Clients), want)
		}
		c := realm.Clients["bench-proxy"]
		if c["secret"] != "client-secret" || c["publicClient"] != false || c["standardFlowEnabled"] != true ||
			c["directAccessGrantsEnabled"] != false {
			t.Errorf("client %v", c)
		}
		if uris, _ := c["redirectUris"].([]any); len(uris) != 1 || uris[0] != "http://127.0.0.1:14180/oauth2/callback" {
			t.Errorf("redirect URIs %v", c["redirectUris"])
		}
		if a, _ := c["attributes"].(map[string]any); a["pkce.code.challenge.method"] != "S256" {
			t.Errorf("attributes %v", c["attributes"])
		}
		mappers, _ := c["protocolMappers"].([]any)
		if len(mappers) != 1 {
			t.Fatalf("mappers %v", c["protocolMappers"])
		}
		m := mappers[0].(map[string]any)
		cfg := m["config"].(map[string]any)
		if m["protocolMapper"] != "oidc-group-membership-mapper" || cfg["claim.name"] != "groups" || cfg["full.path"] != "false" ||
			cfg["id.token.claim"] != "true" || cfg["userinfo.token.claim"] != "true" {
			t.Errorf("groups mapper %v", m)
		}
	}
	check(1)

	kc.ClientSecret = "rotated"
	if err := kc.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fake.Realm("bench").Clients["bench-proxy"]["secret"]; got != "rotated" {
		t.Errorf("secret after setup again: %v", got)
	}
	kc.ClientSecret = "client-secret"
	if err := kc.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	check(1)

	// A realm that lacks the client gets it.
	other := &Keycloak{Client: kc.Client, URL: kc.URL, AdminUser: kc.AdminUser, AdminPassword: kc.AdminPassword,
		ClientID: "another-proxy", ClientSecret: kc.ClientSecret, RedirectURIs: kc.RedirectURIs}
	if err := other.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fake.Realm("bench").Clients["another-proxy"]; got == nil {
		t.Error("setup did not add a missing client")
	}
	check(2)
	// Each Keycloak signs in once and reuses its token for every request.
	if n := fake.SignIns(); n != 2 {
		t.Errorf("%d admin sign-ins, want 2: the token is reused", n)
	}
}

func TestKeycloakSetupErrors(t *testing.T) {
	ctx := context.Background()
	_, kc := newKeycloak(t)
	noSecret := &Keycloak{Client: kc.Client, URL: kc.URL, AdminUser: kc.AdminUser, AdminPassword: kc.AdminPassword}
	if err := noSecret.Setup(ctx); err == nil || !strings.Contains(err.Error(), "no client secret") {
		t.Errorf("no secret: %v", err)
	}
	wrong := &Keycloak{Client: kc.Client, URL: kc.URL, AdminUser: kc.AdminUser, AdminPassword: "wrong", ClientSecret: "s"}
	if err := wrong.Setup(ctx); err == nil || !strings.Contains(err.Error(), "status 401") {
		t.Errorf("wrong admin password: %v", err)
	}
	fake, kc := newKeycloak(t)
	fake.SetFail(func(r *http.Request) int {
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			return http.StatusForbidden
		}
		return 0
	})
	if err := kc.Setup(ctx); err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Errorf("forbidden: %v", err)
	}
	down := &Keycloak{URL: "http://127.0.0.1:1", AdminUser: "a", AdminPassword: "b", ClientSecret: "c"}
	if err := down.Setup(ctx); err == nil {
		t.Error("setup against nothing succeeded")
	}
	notJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>"))
	}))
	defer notJSON.Close()
	bad := &Keycloak{URL: notJSON.URL, AdminUser: "a", AdminPassword: "b", ClientSecret: "c"}
	if err := bad.Setup(ctx); err == nil || !strings.Contains(err.Error(), "no access token") {
		t.Errorf("a token answer that is not JSON: %v", err)
	}
}

// ImportUsers writes the population with its groups and passwords, and a
// second import skips every user and group.
func TestKeycloakImportUsers(t *testing.T) {
	ctx := context.Background()
	fake, kc := newKeycloak(t)
	if err := kc.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	g, err := datasets.Size(100_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	const n = 333
	res, err := kc.ImportUsers(ctx, g, n, 50, 3)
	if err != nil {
		t.Fatal(err)
	}
	realm := fake.Realm("bench")
	if len(realm.Users) != n {
		t.Fatalf("%d users imported, want %d", len(realm.Users), n)
	}
	groups := map[string]bool{}
	for i := range n {
		want := g.User(i)
		got := realm.Users[want.Username]
		if got == nil {
			t.Fatalf("%s missing", want.Username)
		}
		if len(want.Groups) == 0 {
			t.Fatalf("%s is in no group", want.Username)
		}
		wantGroups := slices.Clone(want.Groups)
		for _, x := range wantGroups {
			groups[x] = true
		}
		slices.Sort(wantGroups)
		if got.Password != want.Password || got.Email != want.Email || !got.Enabled || !got.EmailVerified ||
			got.FirstName != "Bench" || got.LastName != "User "+strings.TrimPrefix(want.Username, "u") ||
			!slices.Equal(got.Groups, wantGroups) {
			t.Fatalf("%s: got %+v, want %+v", want.Username, got, want)
		}
	}
	if len(realm.Groups) != len(groups) || res.Groups != int64(len(groups)) {
		t.Errorf("%d groups in the realm, %d imported; the users are in %d", len(realm.Groups), res.Groups, len(groups))
	}
	// One import of the groups, then ceil(333/50) of users.
	if res.Users != n || res.Added != int64(n+len(groups)) || res.Skipped != 0 || res.Imports != 1+7 || res.Retries != 0 {
		t.Errorf("first import: %+v", res)
	}
	again, err := kc.ImportUsers(ctx, g, n, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if again.Added != 0 || again.Skipped != int64(n+len(groups)) || again.Imports != 1+2 {
		t.Errorf("second import: %+v", again)
	}

	checked, err := kc.VerifyUsers(ctx, g, n, 0)
	if err != nil || checked != n {
		t.Fatalf("verify: %d, %v", checked, err)
	}
	// An expired token is replaced once and the request sent again.
	before := fake.SignIns()
	fake.Expire()
	if checked, err := kc.VerifyUsers(ctx, g, n, 10); err != nil || checked != 10 {
		t.Fatalf("verify after expiry: %d, %v", checked, err)
	}
	if fake.SignIns() != before+1 {
		t.Errorf("sign-ins %d, want %d", fake.SignIns(), before+1)
	}
	if checked, err := kc.VerifyUsers(ctx, g, 0, 10); err != nil || checked != 0 {
		t.Errorf("verify of none: %d, %v", checked, err)
	}
	// Users the realm does not hold, or holds differently, fail.
	if _, err := kc.VerifyUsers(ctx, g, n+1, 0); err == nil || !strings.Contains(err.Error(), "found 0 accounts") {
		t.Errorf("a missing user: %v", err)
	}
	u := realm.Users["u7"]
	u.Groups = append(u.Groups, "g999")
	if _, err := kc.VerifyUsers(ctx, g, n, 0); err == nil || !strings.Contains(err.Error(), "u7: groups") {
		t.Errorf("a user in another group: %v", err)
	}
	u.Groups = u.Groups[:len(u.Groups)-1]
	u.Email = "someone@else.example"
	if _, err := kc.VerifyUsers(ctx, g, n, 0); err == nil || !strings.Contains(err.Error(), "u7: enabled true, email") {
		t.Errorf("a user with another email: %v", err)
	}
}

// Answers that may succeed later are retried; others stop the import.
func TestKeycloakImportRetries(t *testing.T) {
	ctx := context.Background()
	g, err := datasets.Size(100_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	fake, kc := newKeycloak(t)
	if err := kc.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	var unavailable atomic.Int32
	fake.SetFail(func(r *http.Request) int {
		if strings.HasSuffix(r.URL.Path, "/partialImport") && unavailable.Add(1) <= 3 {
			return http.StatusServiceUnavailable
		}
		return 0
	})
	res, err := kc.ImportUsers(ctx, g, 40, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Retries != 3 || res.Added == 0 || len(fake.Realm("bench").Users) != 40 {
		t.Errorf("after retries: %+v, %d users", res, len(fake.Realm("bench").Users))
	}

	fake, kc = newKeycloak(t)
	if err := kc.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	var imports atomic.Int32
	fake.SetFail(func(r *http.Request) int {
		// The groups import passes; every users import is refused.
		if strings.HasSuffix(r.URL.Path, "/partialImport") && imports.Add(1) > 1 {
			return http.StatusBadRequest
		}
		return 0
	})
	if _, err := kc.ImportUsers(ctx, g, 2000, 10, 4); err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Errorf("a refused import: %v", err)
	}
	if _, err := kc.ImportUsers(ctx, g, g.Users+1, 10, 4); err == nil {
		t.Error("importing more users than the graph has succeeded")
	}
	fake.SetFail(func(r *http.Request) int {
		if strings.HasSuffix(r.URL.Path, "/partialImport") {
			return http.StatusBadRequest
		}
		return 0
	})
	if _, err := kc.ImportUsers(ctx, g, 5, 10, 1); err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Errorf("a refused groups import: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	fake.SetFail(nil)
	if _, err := kc.ImportUsers(cancelled, g, 500, 10, 1); err == nil {
		t.Error("a cancelled import succeeded")
	}
}
