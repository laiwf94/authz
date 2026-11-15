package fakeidp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestBackchannelLogout(t *testing.T) {
	f := newFixture(t)
	tokens := f.codeTokens(t)
	sids := f.idp.Sessions("alice")
	if len(sids) != 1 {
		t.Fatalf("sessions %v", sids)
	}
	// The login's ID token, and the refreshed one, carry the sid.
	parts := strings.Split(tokens["id_token"].(string), ".")
	if !strings.Contains(decodeSegment(t, parts[1]), `"sid":"`+sids[0]+`"`) {
		t.Fatal("no sid in the ID token")
	}
	resp, body := f.post(t, "/token", refreshForm(tokens["refresh_token"].(string)), "app", "pw")
	var out map[string]any
	json.Unmarshal([]byte(body), &out)
	if resp.StatusCode != 200 || !strings.Contains(decodeSegment(t, strings.Split(out["id_token"].(string), ".")[1]), `"sid":"`+sids[0]+`"`) {
		t.Fatalf("refreshed ID token: %d %s", resp.StatusCode, body)
	}
	_, mdBody := f.get(t, "/.well-known/openid-configuration")
	if !strings.Contains(mdBody, `"backchannel_logout_supported":true`) || !strings.Contains(mdBody, `"backchannel_logout_session_supported":true`) {
		t.Fatalf("discovery: %s", mdBody)
	}

	// Without a registered URI, Logout ends the sessions and sends nothing.
	if n, err := f.idp.Logout(context.Background(), "alice"); n != 0 || err != nil {
		t.Fatalf("no URI: %d %v", n, err)
	}
	if len(f.idp.Sessions("alice")) != 0 || len(f.idp.RefreshTokens("alice")) != 0 {
		t.Fatal("the provider session or refresh token survived")
	}

	// With one, each session gets a logout token naming sub and sid.
	var mu sync.Mutex
	var got []url.Values
	status := http.StatusOK
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("content type %q", r.Header.Get("Content-Type"))
		}
		got = append(got, r.PostForm)
		w.WriteHeader(status)
	}))
	defer rp.Close()
	if !f.idp.SetBackchannelLogoutURI("app", rp.URL+"/bcl") || f.idp.SetBackchannelLogoutURI("nobody", "x") {
		t.Fatal("SetBackchannelLogoutURI")
	}
	f.idp.SetBackchannelClient(rp.Client())
	f.codeTokens(t)
	f.codeTokens(t)
	f.codeTokens(t)
	sids = f.idp.Sessions("alice")
	if n, err := f.idp.Logout(context.Background(), "alice"); n != 3 || err != nil {
		t.Fatalf("logout: %d %v", n, err)
	}
	if len(got) != 3 {
		t.Fatalf("%d requests", len(got))
	}
	for i, form := range got {
		claims := decodeSegment(t, strings.Split(form.Get("logout_token"), ".")[1])
		header := decodeSegment(t, strings.Split(form.Get("logout_token"), ".")[0])
		for _, want := range []string{`"sub":"alice"`, `"sid":"` + sids[i] + `"`, `"aud":"app"`, `"jti":"`, `"exp":`,
			`"events":{"http://schemas.openid.net/event/backchannel-logout":{}}`} {
			if !strings.Contains(claims, want) {
				t.Errorf("token %d lacks %s: %s", i, want, claims)
			}
		}
		if strings.Contains(claims, "nonce") || !strings.Contains(header, `"typ":"logout+jwt"`) {
			t.Errorf("token %d: %s %s", i, header, claims)
		}
	}

	// A relying party that answers 400 or can't be reached is an error;
	// the first is returned, and the other sessions are still sent.
	f.codeTokens(t)
	f.codeTokens(t)
	mu.Lock()
	status, got = http.StatusBadRequest, nil
	mu.Unlock()
	if n, err := f.idp.Logout(context.Background(), "alice"); n != 0 || err == nil || !strings.Contains(err.Error(), "status 400") || len(got) != 2 {
		t.Fatalf("refused: %d %v, %d sent", n, err, len(got))
	}
	f.codeTokens(t)
	f.idp.SetBackchannelLogoutURI("app", "http://127.0.0.1:1/bcl")
	if n, err := f.idp.Logout(context.Background(), "alice"); n != 0 || err == nil {
		t.Fatalf("unreachable: %d %v", n, err)
	}
	f.codeTokens(t)
	f.idp.SetBackchannelLogoutURI("app", "http://bad host/")
	if _, err := f.idp.Logout(context.Background(), "alice"); err == nil {
		t.Fatal("bad URI accepted")
	}

	// A token naming only one of sub and sid, or neither, has only those.
	for _, c := range [][2]string{{"alice", ""}, {"", "s-1"}} {
		tok, err := f.idp.LogoutToken("app", c[0], c[1])
		if err != nil {
			t.Fatal(err)
		}
		claims := decodeSegment(t, strings.Split(tok, ".")[1])
		if strings.Contains(claims, `"sub"`) != (c[0] != "") || strings.Contains(claims, `"sid"`) != (c[1] != "") {
			t.Errorf("%q: %s", c, claims)
		}
	}
	if f.idp.Issuer() != f.idp.cfg.Issuer {
		t.Fatal("issuer")
	}
	// No typ header at all.
	tok, _ := f.idp.SignJWTType("", map[string]any{"a": 1})
	if strings.Contains(decodeSegment(t, strings.Split(tok, ".")[0]), "typ") {
		t.Fatal("typ set")
	}
}
