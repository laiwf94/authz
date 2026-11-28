package productstest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The management and user API, request by request, with what the fake
// refuses.
func TestZitadelAPI(t *testing.T) {
	z := &Zitadel{Token: "pat"}
	code, body := send(t, z, http.MethodPost, "/management/v1/projects", "pat", `{"name":"p","projectRoleAssertion":true}`)
	var p struct{ ID string }
	if json.Unmarshal([]byte(body), &p); code != http.StatusOK || p.ID == "" {
		t.Fatalf("project: %d %s", code, body)
	}
	pp := "/management/v1/projects/" + p.ID
	code, body = send(t, z, http.MethodPost, pp+"/apps/oidc", "pat",
		`{"name":"a","redirectUris":["http://x/cb"],"responseTypes":["OIDC_RESPONSE_TYPE_CODE"],"authMethodType":"OIDC_AUTH_METHOD_TYPE_NONE"}`)
	var app struct{ AppID, ClientID string }
	if json.Unmarshal([]byte(body), &app); code != http.StatusOK || app.ClientID == "" {
		t.Fatalf("app: %d %s", code, body)
	}
	human := func(id, user string) string {
		return `{"userId":"` + id + `","username":"` + user + `","organization":{"orgId":"` + ZitadelOrgID + `"},` +
			`"profile":{"givenName":"A","familyName":"B"},"email":{"email":"a@x","isVerified":true},"password":{"password":"pw-0123456789"}}`
	}
	for _, c := range []struct {
		name, method, path, auth, body string
		want                           int
	}{
		{"no token", http.MethodGet, "/management/v1/orgs/me", "", "", http.StatusUnauthorized},
		{"wrong token", http.MethodGet, "/management/v1/orgs/me", "x", "", http.StatusUnauthorized},
		{"org", http.MethodGet, "/management/v1/orgs/me", "pat", "", http.StatusOK},
		{"unknown path", http.MethodGet, "/admin/v1/orgs", "pat", "", http.StatusNotFound},
		{"unknown field", http.MethodPost, "/management/v1/projects", "pat", `{"name":"q","bogus":1}`, http.StatusBadRequest},
		{"project again", http.MethodPost, "/management/v1/projects", "pat", `{"name":"p"}`, http.StatusConflict},
		{"bad search", http.MethodPost, "/management/v1/projects/_search", "pat", `{"queries":1}`, http.StatusBadRequest},
		{"unchanged project", http.MethodPut, pp, "pat", `{"name":"p","projectRoleAssertion":true}`, http.StatusBadRequest},
		{"bad project update", http.MethodPut, pp, "pat", `{"name":1}`, http.StatusBadRequest},
		{"update missing project", http.MethodPut, "/management/v1/projects/9", "pat", `{"name":"p"}`, http.StatusNotFound},
		{"roles of a missing project", http.MethodPost, "/management/v1/projects/9/roles", "pat", `{}`, http.StatusNotFound},
		{"role without a name", http.MethodPost, pp + "/roles", "pat", `{"roleKey":"g1"}`, http.StatusBadRequest},
		{"bad role", http.MethodPost, pp + "/roles", "pat", `{"roleKey":1}`, http.StatusBadRequest},
		{"role", http.MethodPost, pp + "/roles", "pat", `{"roleKey":"g1","displayName":"g1"}`, http.StatusOK},
		{"role again", http.MethodPost, pp + "/roles", "pat", `{"roleKey":"g1","displayName":"g1"}`, http.StatusConflict},
		{"too many roles", http.MethodPost, pp + "/roles/_search", "pat", `{"query":{"limit":5000}}`, http.StatusBadRequest},
		{"bad role search", http.MethodPost, pp + "/roles/_search", "pat", `{"query":1}`, http.StatusBadRequest},
		{"app without a name", http.MethodPost, pp + "/apps/oidc", "pat", `{"redirectUris":[]}`, http.StatusBadRequest},
		{"app again", http.MethodPost, pp + "/apps/oidc", "pat", `{"name":"a"}`, http.StatusConflict},
		{"bad app", http.MethodPost, pp + "/apps/oidc", "pat", `{"name":"b","clientSecret":"x"}`, http.StatusBadRequest},
		{"bad app search", http.MethodPost, pp + "/apps/_search", "pat", `[]`, http.StatusBadRequest},
		{"unchanged app", http.MethodPut, pp + "/apps/" + app.AppID + "/oidc_config", "pat",
			`{"redirectUris":["http://x/cb"],"responseTypes":["OIDC_RESPONSE_TYPE_CODE"],"authMethodType":"OIDC_AUTH_METHOD_TYPE_NONE"}`, http.StatusBadRequest},
		{"app name in a config", http.MethodPut, pp + "/apps/" + app.AppID + "/oidc_config", "pat", `{"name":"a"}`, http.StatusBadRequest},
		{"bad app config", http.MethodPut, pp + "/apps/" + app.AppID + "/oidc_config", "pat", `{"devMode":"yes"}`, http.StatusBadRequest},
		{"config of a missing app", http.MethodPut, pp + "/apps/9/oidc_config", "pat", `{"devMode":true}`, http.StatusNotFound},
		{"other project path", http.MethodGet, pp + "/members", "pat", "", http.StatusNotFound},
		{"user", http.MethodPost, "/v2/users/human", "pat", human("u1", "u1"), http.StatusOK},
		{"user ID again", http.MethodPost, "/v2/users/human", "pat", human("u1", "x1"), http.StatusBadRequest},
		{"user name again", http.MethodPost, "/v2/users/human", "pat", human("u2", "u1"), http.StatusConflict},
		{"short password", http.MethodPost, "/v2/users/human", "pat", strings.Replace(human("u3", "u3"), "pw-0123456789", "short", 1), http.StatusBadRequest},
		{"other org", http.MethodPost, "/v2/users/human", "pat", strings.Replace(human("u3", "u3"), ZitadelOrgID, "1", 1), http.StatusBadRequest},
		{"bad user", http.MethodPost, "/v2/users/human", "pat", `{"userId":1}`, http.StatusBadRequest},
		{"missing user", http.MethodGet, "/v2/users/u9", "pat", "", http.StatusNotFound},
		{"grant of a missing user", http.MethodPost, "/management/v1/users/u9/grants", "pat", `{"projectId":"` + p.ID + `"}`, http.StatusNotFound},
		{"grant on a missing project", http.MethodPost, "/management/v1/users/u1/grants", "pat", `{"projectId":"9"}`, http.StatusBadRequest},
		{"grant of a missing role", http.MethodPost, "/management/v1/users/u1/grants", "pat", `{"projectId":"` + p.ID + `","roleKeys":["g2"]}`, http.StatusBadRequest},
		{"bad grant", http.MethodPost, "/management/v1/users/u1/grants", "pat", `{"roleKeys":"g1"}`, http.StatusBadRequest},
		{"grant", http.MethodPost, "/management/v1/users/u1/grants", "pat", `{"projectId":"` + p.ID + `","roleKeys":["g1"]}`, http.StatusOK},
		{"grant again", http.MethodPost, "/management/v1/users/u1/grants", "pat", `{"projectId":"` + p.ID + `","roleKeys":["g1"]}`, http.StatusConflict},
		{"bad grant search", http.MethodPost, "/management/v1/users/grants/_search", "pat", `{"queries":{}}`, http.StatusBadRequest},
	} {
		if code, body := send(t, z, c.method, c.path, c.auth, c.body); code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, code, body, c.want)
		}
	}
	code, body = send(t, z, http.MethodPost, "/management/v1/users/grants/_search", "pat",
		`{"queries":[{"userIdQuery":{"userId":"u1"}},{"projectIdQuery":{"projectId":"`+p.ID+`"}}]}`)
	if code != http.StatusOK || !strings.Contains(body, `"roleKeys":["g1"]`) {
		t.Errorf("grants: %d %s", code, body)
	}
	code, body = send(t, z, http.MethodGet, "/v2/users/u1", "pat", "")
	if code != http.StatusOK || !strings.Contains(body, `"state":"USER_STATE_ACTIVE"`) || !strings.Contains(body, `"isVerified":true`) {
		t.Errorf("user: %d %s", code, body)
	}
	// A POST needs a JSON body.
	req := httptest.NewRequest(http.MethodPost, "/management/v1/projects", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer pat")
	rec := httptest.NewRecorder()
	z.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST without a content type: %d", rec.Code)
	}
	if z.Project("nope") != nil || z.User("u1") == nil || z.Users() != 1 {
		t.Error("state accessors")
	}
}

// The sign-in endpoints refuse a wrong client, redirect URI, PKCE
// verifier, CSRF token or auth request.
func TestZitadelLogin(t *testing.T) {
	z := &Zitadel{Token: "pat"}
	_, body := send(t, z, http.MethodPost, "/management/v1/projects", "pat", `{"name":"p","projectRoleAssertion":true}`)
	var p struct{ ID string }
	json.Unmarshal([]byte(body), &p)
	_, body = send(t, z, http.MethodPost, "/management/v1/projects/"+p.ID+"/apps/oidc", "pat",
		`{"name":"a","redirectUris":["http://x/cb"],"authMethodType":"OIDC_AUTH_METHOD_TYPE_NONE","idTokenRoleAssertion":true}`)
	var app struct{ ClientID string }
	json.Unmarshal([]byte(body), &app)
	send(t, z, http.MethodPost, "/v2/users/human", "pat", `{"userId":"u1","username":"u1","organization":{"orgId":"`+ZitadelOrgID+
		`"},"profile":{"givenName":"A","familyName":"B"},"email":{"email":"a@x","isVerified":true},"password":{"password":"pw-0123456789"}}`)
	send(t, z, http.MethodPost, "/management/v1/projects/"+p.ID+"/roles", "pat", `{"roleKey":"g1","displayName":"g1"}`)
	send(t, z, http.MethodPost, "/management/v1/users/u1/grants", "pat", `{"projectId":"`+p.ID+`","roleKeys":["g1"]}`)

	do := func(method, target string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		z.ServeHTTP(rec, req)
		return rec
	}
	sum := sha256.Sum256([]byte("verifier"))
	q := url.Values{"client_id": {app.ClientID}, "redirect_uri": {"http://x/cb"}, "response_type": {"code"}, "scope": {"openid"},
		"state": {"s"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	for name, change := range map[string]func(url.Values){
		"unknown client":  func(v url.Values) { v.Set("client_id", "nope") },
		"other redirect":  func(v url.Values) { v.Set("redirect_uri", "http://y/cb") },
		"no openid scope": func(v url.Values) { v.Set("scope", "email") },
		"no PKCE":         func(v url.Values) { v.Del("code_challenge") },
	} {
		v := url.Values{}
		for k, x := range q {
			v[k] = x
		}
		change(v)
		if rec := do(http.MethodGet, "/oauth/v2/authorize?"+v.Encode(), nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	rec := do(http.MethodGet, "/oauth/v2/authorize?"+q.Encode(), nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	id := loc.Query().Get("authRequestID")
	if rec.Code != http.StatusFound || id == "" {
		t.Fatalf("authorize: %d %v", rec.Code, loc)
	}
	csrf := &http.Cookie{Name: "zitadel.login.csrf", Value: zitadelCSRF}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"login page of no request": do(http.MethodGet, "/ui/login/login?authRequestID=nope", nil),
		"name without CSRF":        do(http.MethodPost, "/ui/login/loginname", url.Values{"authRequestID": {id}, "loginName": {"u1"}}),
		"name of no request": do(http.MethodPost, "/ui/login/loginname",
			url.Values{"authRequestID": {"nope"}, "gorilla.csrf.Token": {zitadelCSRF}}, csrf),
		"callback before sign-in": do(http.MethodGet, "/oauth/v2/authorize/callback?id="+id, nil),
		"other page":              do(http.MethodGet, "/ui/login/register", nil),
	} {
		if rec.Code == http.StatusOK || rec.Code == http.StatusFound {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if rec := do(http.MethodGet, "/ui/login/login?authRequestID="+id, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="loginName"`) {
		t.Errorf("login page: %d", rec.Code)
	}
	form := url.Values{"authRequestID": {id}, "gorilla.csrf.Token": {zitadelCSRF}, "loginName": {"u1"}}
	if rec := do(http.MethodPost, "/ui/login/loginname", form, csrf); !strings.Contains(rec.Body.String(), `type="password"`) {
		t.Errorf("password page: %d %s", rec.Code, rec.Body)
	}
	form.Set("password", "wrong")
	if rec := do(http.MethodPost, "/ui/login/password", form, csrf); !strings.Contains(rec.Body.String(), "invalid") {
		t.Errorf("wrong password: %d", rec.Code)
	}
	form.Set("password", "pw-0123456789")
	if rec := do(http.MethodPost, "/ui/login/password", form, csrf); rec.Code != http.StatusFound {
		t.Errorf("password: %d", rec.Code)
	}
	rec = do(http.MethodGet, "/oauth/v2/authorize/callback?id="+id, nil)
	cb, _ := url.Parse(rec.Header().Get("Location"))
	code := cb.Query().Get("code")
	if rec.Code != http.StatusFound || code == "" || cb.Query().Get("state") != "s" {
		t.Fatalf("callback: %d %v", rec.Code, cb)
	}
	token := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {app.ClientID}, "redirect_uri": {"http://x/cb"},
		"code_verifier": {"wrong"}}
	if rec := do(http.MethodPost, "/oauth/v2/token", token); rec.Code != http.StatusBadRequest {
		t.Errorf("wrong verifier: %d", rec.Code)
	}
	token.Set("code_verifier", "verifier")
	rec = do(http.MethodPost, "/oauth/v2/token", token)
	var tok struct {
		IDToken string `json:"id_token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &tok)
	parts := strings.Split(tok.IDToken, ".")
	if rec.Code != http.StatusOK || len(parts) != 3 {
		t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if !strings.Contains(string(claims), `"urn:zitadel:iam:org:project:roles":{"g1":`) || !strings.Contains(string(claims), `"sub":"u1"`) {
		t.Errorf("claims %s", claims)
	}
	if rec := do(http.MethodPost, "/oauth/v2/token", token); rec.Code != http.StatusBadRequest {
		t.Errorf("a code redeemed twice: %d", rec.Code)
	}
}
