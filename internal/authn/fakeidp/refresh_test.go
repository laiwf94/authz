package fakeidp

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// codeTokens signs alice in and redeems the code, returning the token
// response.
func (f *fixture) codeTokens(t *testing.T) map[string]any {
	t.Helper()
	q := goodAuthorize()
	q.Set("username", "alice")
	q.Set("password", "alice-pass")
	resp, _ := f.post(t, "/authorize", q, "", "")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {"https://app/cb"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
	resp, body := f.post(t, "/token", form, "app", "pw")
	if resp.StatusCode != 200 {
		t.Fatalf("code exchange: %d %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func refreshForm(tok string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}}
}

func TestRefreshRotatesAndEnds(t *testing.T) {
	f := newFixture(t)
	first, _ := f.codeTokens(t)["refresh_token"].(string)
	if first == "" || len(f.idp.RefreshTokens("alice")) != 1 {
		t.Fatalf("no refresh token issued (%d live)", len(f.idp.RefreshTokens("alice")))
	}
	resp, body := f.post(t, "/token", refreshForm(first), "app", "pw")
	if resp.StatusCode != 200 {
		t.Fatalf("refresh: %d %s", resp.StatusCode, body)
	}
	var out map[string]any
	json.Unmarshal([]byte(body), &out)
	second, _ := out["refresh_token"].(string)
	if second == "" || second == first || out["access_token"] == "" || out["id_token"] == "" {
		t.Fatal("refresh response lacks a rotated token, an access token or an ID token")
	}
	// The ID token is for the same user and carries no nonce.
	parts := strings.Split(out["id_token"].(string), ".")
	if len(parts) != 3 || strings.Contains(decodeSegment(t, parts[1]), `"nonce"`) || !strings.Contains(decodeSegment(t, parts[1]), `"sub":"alice"`) {
		t.Fatal("refreshed ID token claims")
	}
	// Rotation: the first token no longer works.
	if resp, body := f.post(t, "/token", refreshForm(first), "app", "pw"); resp.StatusCode != 400 || !strings.Contains(body, "invalid_grant") {
		t.Fatalf("reused token: %d %s", resp.StatusCode, body)
	}
	if live := f.idp.RefreshTokens("alice"); len(live) != 1 || live[0] != second {
		t.Fatalf("%d live tokens after rotation", len(live))
	}
	// Ending the user's sessions revokes the token.
	if n := f.idp.EndSessions("alice"); n != 1 {
		t.Fatalf("EndSessions = %d", n)
	}
	if resp, body := f.post(t, "/token", refreshForm(second), "app", "pw"); resp.StatusCode != 400 || !strings.Contains(body, "invalid_grant") {
		t.Fatalf("after EndSessions: %d %s", resp.StatusCode, body)
	}
	if f.idp.EndSessions("alice") != 0 || len(f.idp.RefreshTokens("bob")) != 0 {
		t.Fatal("counts")
	}
}

func TestRefreshErrorsAndOutage(t *testing.T) {
	f := newFixture(t)
	tok, _ := f.codeTokens(t)["refresh_token"].(string)
	if resp, _ := f.post(t, "/token", refreshForm(tok), "app", "wrong"); resp.StatusCode != 401 {
		t.Fatal("bad client secret accepted")
	}
	if resp, body := f.post(t, "/token", refreshForm("nope"), "app", "pw"); resp.StatusCode != 400 || !strings.Contains(body, "invalid_grant") {
		t.Fatalf("unknown token: %s", body)
	}
	if resp, body := f.post(t, "/token", url.Values{"grant_type": {"password"}}, "app", "pw"); resp.StatusCode != 400 || !strings.Contains(body, "unsupported_grant_type") {
		t.Fatalf("password grant: %s", body)
	}
	f.idp.SetTokenEndpointDown(true)
	if resp, body := f.post(t, "/token", refreshForm(tok), "app", "pw"); resp.StatusCode != 503 || !strings.Contains(body, "temporarily_unavailable") {
		t.Fatalf("down: %d %s", resp.StatusCode, body)
	}
	f.idp.SetTokenEndpointDown(false)
	// The outage didn't use the token up.
	if resp, body := f.post(t, "/token", refreshForm(tok), "app", "pw"); resp.StatusCode != 200 {
		t.Fatalf("after the outage: %d %s", resp.StatusCode, body)
	}
}

func decodeSegment(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
