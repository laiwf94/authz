package productstest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Zitadel is a fake of the parts of Zitadel v4 that bench/products uses:
// the management API (the token's organization, projects, roles, OpenID
// Connect applications and user grants), the user API's new humans and
// reads, and a sign-in through login v1 with the authorization code flow
// and PKCE, ending in an ID token that carries the project's roles.
//
// It refuses what Zitadel refuses (a missing token, a project or
// application name that exists, an update that changes nothing, a user ID
// or user name that exists, a grant of a role the project does not have, a
// wrong PKCE verifier) and, unlike Zitadel, which drops them, fields it
// does not know, so a typo in a request fails a test. With Lag set, what a
// request writes shows in searches and reads only Lag reads later, as
// Zitadel's projections trail its event store.
type Zitadel struct {
	Token string
	// Lag is how many reads pass before a write shows in reads.
	Lag int
	// Issuer is the ID token's iss; empty means http:// and the host the
	// token endpoint was asked at, Zitadel's external address.
	Issuer string

	mu       sync.Mutex
	fail     func(r *http.Request) int
	reads    int
	ids      int
	projects []*ZitadelProject
	users    map[string]*ZitadelUser // by ID
	requests map[string]*zitadelAuthRequest
	codes    map[string]*zitadelAuthRequest
	SignIns  int
}

// ZitadelProject is a project with its roles and applications.
type ZitadelProject struct {
	ID, Name             string
	ProjectRoleAssertion bool
	Roles                []string
	Apps                 []*ZitadelApp
	Updates              int
	visible              int
	roleVisible          map[string]int
}

// ZitadelApp is an OpenID Connect application.
type ZitadelApp struct {
	ID, Name, ClientID string
	Config             map[string]any
	Updates            int
	visible            int
}

// ZitadelUser is a human user with its grants.
type ZitadelUser struct {
	ID, Username, Email, GivenName, FamilyName string
	EmailVerified, PasswordChangeRequired      bool
	Password, Org                              string
	Grants                                     map[string][]string // project ID -> role keys
	visible                                    int
}

type zitadelAuthRequest struct {
	id, clientID, redirect, state, challenge string
	user                                     *ZitadelUser
	project                                  *ZitadelProject
}

// ZitadelOrgID is the organization of the token's user.
const ZitadelOrgID = "300000000000000001"

// SetFail makes fn see each request first: a status other than 0 is
// answered instead of the fake's. nil clears it.
func (z *Zitadel) SetFail(fn func(r *http.Request) int) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.fail = fn
}

// SetLag sets Lag while the fake serves.
func (z *Zitadel) SetLag(n int) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.Lag = n
}

// Project returns the named project, or nil. The fake keeps it; read it
// only while no request runs.
func (z *Zitadel) Project(name string) *ZitadelProject {
	z.mu.Lock()
	defer z.mu.Unlock()
	for _, p := range z.projects {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// Users returns the number of users.
func (z *Zitadel) Users() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return len(z.users)
}

// User returns a user by ID, or nil, with the same caveat as Project.
func (z *Zitadel) User(id string) *ZitadelUser {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.users[id]
}

func (z *Zitadel) id() string {
	z.ids++
	return strconv.Itoa(300000000000000100 + z.ids)
}

// shown is the read count after which a write made now is visible.
func (z *Zitadel) shown() int { return z.reads + z.Lag }

func zerror(w http.ResponseWriter, status int, msg string) {
	codes := map[int]int{http.StatusBadRequest: 9, http.StatusNotFound: 5, http.StatusConflict: 6, http.StatusUnauthorized: 16}
	reply(w, status, map[string]any{"code": codes[status], "message": msg, "details": []any{}})
}

type zitadelNameQuery struct {
	Queries []struct {
		NameQuery struct {
			Name   string `json:"name"`
			Method string `json:"method"`
		} `json:"nameQuery"`
	} `json:"queries"`
}

func (q zitadelNameQuery) match(name string) bool {
	for _, x := range q.Queries {
		if x.NameQuery.Method != "TEXT_QUERY_METHOD_EQUALS" || x.NameQuery.Name != name {
			return false
		}
	}
	return true
}

type zitadelProjectRep struct {
	Name                 string `json:"name"`
	ProjectRoleAssertion bool   `json:"projectRoleAssertion"`
}

// zitadelOIDCRep is the configuration of an application, with the
// management API's JSON names.
type zitadelOIDCRep struct {
	Name                     string          `json:"name,omitempty"`
	RedirectURIs             []string        `json:"redirectUris"`
	ResponseTypes            []string        `json:"responseTypes"`
	GrantTypes               []string        `json:"grantTypes"`
	AppType                  string          `json:"appType"`
	AuthMethodType           string          `json:"authMethodType"`
	DevMode                  bool            `json:"devMode"`
	AccessTokenType          string          `json:"accessTokenType"`
	IDTokenRoleAssertion     bool            `json:"idTokenRoleAssertion"`
	IDTokenUserinfoAssertion bool            `json:"idTokenUserinfoAssertion"`
	LoginVersion             json.RawMessage `json:"loginVersion"`
}

// config is rep as the API answers it: zero values left out.
func (rep zitadelOIDCRep) config() map[string]any {
	rep.Name = ""
	b, _ := json.Marshal(rep)
	var m map[string]any
	json.Unmarshal(b, &m)
	for k, v := range m {
		if v == nil || v == false || v == "" || v == "OIDC_APP_TYPE_WEB" || v == "OIDC_AUTH_METHOD_TYPE_BASIC" || v == "OIDC_TOKEN_TYPE_BEARER" {
			delete(m, k)
		}
	}
	return m
}

type zitadelHuman struct {
	UserID       string            `json:"userId"`
	Username     string            `json:"username"`
	Organization map[string]string `json:"organization"`
	Profile      struct {
		GivenName   string `json:"givenName"`
		FamilyName  string `json:"familyName"`
		DisplayName string `json:"displayName"`
	} `json:"profile"`
	Email struct {
		Email      string `json:"email"`
		IsVerified bool   `json:"isVerified"`
	} `json:"email"`
	Password struct {
		Password       string `json:"password"`
		ChangeRequired bool   `json:"changeRequired"`
	} `json:"password"`
}

// ServeHTTP implements http.Handler.
func (z *Zitadel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.fail != nil {
		if code := z.fail(r); code != 0 {
			zerror(w, code, "failed on purpose")
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/oauth/") || strings.HasPrefix(r.URL.Path, "/ui/login/") {
		z.oidc(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+z.Token || z.Token == "" {
		zerror(w, http.StatusUnauthorized, "Errors.Token.Invalid (AUTH-7fs1e)")
		return
	}
	if r.Method != http.MethodGet && r.Header.Get("Content-Type") != "application/json" {
		zerror(w, http.StatusBadRequest, "content type")
		return
	}
	if z.users == nil {
		z.users = map[string]*ZitadelUser{}
	}
	read := r.Method == http.MethodGet || strings.HasSuffix(r.URL.Path, "/_search")
	if read {
		z.reads++
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	path := r.Method + " " + r.URL.Path
	switch {
	case path == "GET /management/v1/orgs/me":
		reply(w, http.StatusOK, map[string]any{"org": map[string]string{"id": ZitadelOrgID, "name": "bench", "primaryDomain": "bench.localhost"}})
	case path == "POST /management/v1/projects/_search":
		var q zitadelNameQuery
		if !decode(w, r, &q) {
			return
		}
		out := []map[string]any{}
		for _, p := range z.projects {
			if p.visible <= z.reads && q.match(p.Name) {
				m := map[string]any{"id": p.ID, "name": p.Name}
				if p.ProjectRoleAssertion {
					m["projectRoleAssertion"] = true
				}
				out = append(out, m)
			}
		}
		reply(w, http.StatusOK, map[string]any{"details": map[string]string{"totalResult": strconv.Itoa(len(out))}, "result": out})
	case path == "POST /management/v1/projects":
		var rep zitadelProjectRep
		if !decode(w, r, &rep) {
			return
		}
		for _, p := range z.projects {
			if p.Name == rep.Name {
				zerror(w, http.StatusConflict, "Errors.Project.AlreadyExists")
				return
			}
		}
		p := &ZitadelProject{ID: z.id(), Name: rep.Name, ProjectRoleAssertion: rep.ProjectRoleAssertion, visible: z.shown(), roleVisible: map[string]int{}}
		z.projects = append(z.projects, p)
		reply(w, http.StatusOK, map[string]any{"id": p.ID})
	case len(parts) == 4 && parts[2] == "projects" && r.Method == http.MethodPut:
		p := z.projectByID(parts[3])
		if p == nil {
			zerror(w, http.StatusNotFound, "Errors.Project.NotFound")
			return
		}
		var rep zitadelProjectRep
		if !decode(w, r, &rep) {
			return
		}
		if rep.Name == p.Name && rep.ProjectRoleAssertion == p.ProjectRoleAssertion {
			zerror(w, http.StatusBadRequest, "Errors.Project.NotChanged")
			return
		}
		p.Name, p.ProjectRoleAssertion = rep.Name, rep.ProjectRoleAssertion
		p.Updates++
		reply(w, http.StatusOK, map[string]any{})
	case len(parts) >= 5 && parts[2] == "projects":
		p := z.projectByID(parts[3])
		if p == nil {
			zerror(w, http.StatusNotFound, "Errors.Project.NotFound")
			return
		}
		z.project(w, r, p, parts[4:])
	case path == "POST /v2/users/human":
		var h zitadelHuman
		if !decode(w, r, &h) {
			return
		}
		if h.Organization["orgId"] != ZitadelOrgID || h.UserID == "" || h.Username == "" || h.Email.Email == "" ||
			h.Profile.GivenName == "" || h.Profile.FamilyName == "" || len(h.Password.Password) < 12 {
			zerror(w, http.StatusBadRequest, "invalid AddHumanUserRequest")
			return
		}
		if z.users[h.UserID] != nil {
			zerror(w, http.StatusConflict, "Errors.User.AlreadyExisting")
			return
		}
		for _, u := range z.users {
			if u.Username == h.Username {
				zerror(w, http.StatusConflict, "Errors.User.AlreadyExists")
				return
			}
		}
		z.users[h.UserID] = &ZitadelUser{ID: h.UserID, Username: h.Username, Email: h.Email.Email, GivenName: h.Profile.GivenName,
			FamilyName: h.Profile.FamilyName, EmailVerified: h.Email.IsVerified, PasswordChangeRequired: h.Password.ChangeRequired,
			Password: h.Password.Password, Org: ZitadelOrgID, Grants: map[string][]string{}, visible: z.shown()}
		reply(w, http.StatusOK, map[string]any{"userId": h.UserID, "details": map[string]string{"resourceOwner": ZitadelOrgID}})
	case len(parts) == 3 && parts[0] == "v2" && parts[1] == "users" && r.Method == http.MethodGet:
		u := z.users[parts[2]]
		if u == nil || u.visible > z.reads {
			zerror(w, http.StatusNotFound, "Errors.User.NotFound")
			return
		}
		human := map[string]any{"email": map[string]any{"email": u.Email, "isVerified": u.EmailVerified},
			"profile": map[string]string{"givenName": u.GivenName, "familyName": u.FamilyName}}
		if u.PasswordChangeRequired {
			human["passwordChangeRequired"] = true
		}
		reply(w, http.StatusOK, map[string]any{"user": map[string]any{"userId": u.ID, "username": u.Username,
			"state": "USER_STATE_ACTIVE", "human": human}})
	case len(parts) == 5 && parts[2] == "users" && parts[4] == "grants" && r.Method == http.MethodPost:
		var g struct {
			ProjectID string   `json:"projectId"`
			RoleKeys  []string `json:"roleKeys"`
		}
		if !decode(w, r, &g) {
			return
		}
		u, p := z.users[parts[3]], z.projectByID(g.ProjectID)
		switch {
		case u == nil:
			zerror(w, http.StatusNotFound, "Errors.User.NotFound")
			return
		case p == nil:
			zerror(w, http.StatusBadRequest, "Errors.Project.NotFound")
			return
		case u.Grants[p.ID] != nil:
			zerror(w, http.StatusConflict, "Errors.UserGrant.AlreadyExists")
			return
		}
		for _, k := range g.RoleKeys {
			if v, ok := p.roleVisible[k]; !ok || v > z.reads {
				// Zitadel checks the roles against its projection.
				zerror(w, http.StatusBadRequest, "Errors.Project.Role.NotFound")
				return
			}
		}
		u.Grants[p.ID] = slices.Clone(g.RoleKeys)
		reply(w, http.StatusOK, map[string]any{"userGrantId": z.id()})
	case path == "POST /management/v1/users/grants/_search":
		var q struct {
			Queries []struct {
				UserIDQuery *struct {
					UserID string `json:"userId"`
				} `json:"userIdQuery"`
				ProjectIDQuery *struct {
					ProjectID string `json:"projectId"`
				} `json:"projectIdQuery"`
			} `json:"queries"`
		}
		if !decode(w, r, &q) {
			return
		}
		var user, project string
		for _, x := range q.Queries {
			if x.UserIDQuery != nil {
				user = x.UserIDQuery.UserID
			}
			if x.ProjectIDQuery != nil {
				project = x.ProjectIDQuery.ProjectID
			}
		}
		out := []map[string]any{}
		if u := z.users[user]; u != nil && u.visible <= z.reads {
			for pid, keys := range u.Grants {
				if project == "" || pid == project {
					out = append(out, map[string]any{"userId": u.ID, "projectId": pid, "roleKeys": keys})
				}
			}
		}
		reply(w, http.StatusOK, map[string]any{"result": out})
	default:
		zerror(w, http.StatusNotFound, "Not Found")
	}
}

func (z *Zitadel) projectByID(id string) *ZitadelProject {
	for _, p := range z.projects {
		if p.ID == id {
			return p
		}
	}
	return nil
}

func (z *Zitadel) project(w http.ResponseWriter, r *http.Request, p *ZitadelProject, rest []string) {
	switch path := r.Method + " " + strings.Join(rest, "/"); {
	case path == "POST roles/_search":
		var q struct {
			Query struct {
				Offset int  `json:"offset"`
				Limit  int  `json:"limit"`
				Asc    bool `json:"asc"`
			} `json:"query"`
		}
		if !decode(w, r, &q) {
			return
		}
		if q.Query.Limit > 1000 {
			zerror(w, http.StatusBadRequest, "Errors.Query.LimitExceeded")
			return
		}
		var keys []string
		for _, k := range p.Roles {
			if p.roleVisible[k] <= z.reads {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		out := []map[string]string{}
		for i := q.Query.Offset; i < len(keys) && len(out) < q.Query.Limit; i++ {
			out = append(out, map[string]string{"key": keys[i], "displayName": keys[i]})
		}
		reply(w, http.StatusOK, map[string]any{"details": map[string]string{"totalResult": strconv.Itoa(len(keys))}, "result": out})
	case path == "POST roles":
		var rep struct {
			RoleKey     string `json:"roleKey"`
			DisplayName string `json:"displayName"`
		}
		if !decode(w, r, &rep) {
			return
		}
		if rep.RoleKey == "" || rep.DisplayName == "" {
			zerror(w, http.StatusBadRequest, "invalid AddProjectRoleRequest")
			return
		}
		if slices.Contains(p.Roles, rep.RoleKey) {
			zerror(w, http.StatusConflict, "Errors.Project.Role.AlreadyExists")
			return
		}
		p.Roles = append(p.Roles, rep.RoleKey)
		p.roleVisible[rep.RoleKey] = z.shown()
		reply(w, http.StatusOK, map[string]any{})
	case path == "POST apps/_search":
		var q zitadelNameQuery
		if !decode(w, r, &q) {
			return
		}
		out := []map[string]any{}
		for _, a := range p.Apps {
			if a.visible <= z.reads && q.match(a.Name) {
				cfg := map[string]any{"clientId": a.ClientID}
				for k, v := range a.Config {
					cfg[k] = v
				}
				out = append(out, map[string]any{"id": a.ID, "name": a.Name, "oidcConfig": cfg})
			}
		}
		reply(w, http.StatusOK, map[string]any{"result": out})
	case path == "POST apps/oidc":
		var rep zitadelOIDCRep
		if !decode(w, r, &rep) {
			return
		}
		if rep.Name == "" {
			zerror(w, http.StatusBadRequest, "invalid AddOIDCAppRequest")
			return
		}
		for _, a := range p.Apps {
			if a.Name == rep.Name {
				zerror(w, http.StatusConflict, "Errors.Project.App.AlreadyExists")
				return
			}
		}
		a := &ZitadelApp{ID: z.id(), Name: rep.Name, Config: rep.config(), visible: z.shown()}
		a.ClientID = a.ID + "@" + p.Name
		p.Apps = append(p.Apps, a)
		reply(w, http.StatusOK, map[string]any{"appId": a.ID, "clientId": a.ClientID})
	case len(rest) == 3 && rest[0] == "apps" && rest[2] == "oidc_config" && r.Method == http.MethodPut:
		var rep zitadelOIDCRep
		if !decode(w, r, &rep) {
			return
		}
		for _, a := range p.Apps {
			if a.ID == rest[1] {
				if rep.Name != "" {
					zerror(w, http.StatusBadRequest, "unknown field name")
					return
				}
				cfg := rep.config()
				if reflect.DeepEqual(cfg, a.Config) {
					zerror(w, http.StatusBadRequest, "Errors.Project.App.OIDCConfigInvalid: not changed")
					return
				}
				a.Config = cfg
				a.Updates++
				reply(w, http.StatusOK, map[string]any{})
				return
			}
		}
		zerror(w, http.StatusNotFound, "Errors.Project.App.NotFound")
	default:
		zerror(w, http.StatusNotFound, "Not Found")
	}
}

// app returns the application of a client ID and its project.
func (z *Zitadel) app(clientID string) (*ZitadelApp, *ZitadelProject) {
	for _, p := range z.projects {
		for _, a := range p.Apps {
			if a.ClientID == clientID {
				return a, p
			}
		}
	}
	return nil, nil
}

const zitadelCSRF = "csrf-token-1"

func (z *Zitadel) page(w http.ResponseWriter, body string) {
	http.SetCookie(w, &http.Cookie{Name: "zitadel.login.csrf", Value: zitadelCSRF, HttpOnly: true})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, body)
}

// oidc serves the authorization endpoint, login v1's two pages, the
// callback and the token endpoint.
func (z *Zitadel) oidc(w http.ResponseWriter, r *http.Request) {
	if z.requests == nil {
		z.requests, z.codes = map[string]*zitadelAuthRequest{}, map[string]*zitadelAuthRequest{}
	}
	r.ParseForm()
	f := r.Form
	form := func() (*zitadelAuthRequest, bool) {
		c, err := r.Cookie("zitadel.login.csrf")
		if r.Method != http.MethodPost || err != nil || c.Value != zitadelCSRF || f.Get("gorilla.csrf.Token") != zitadelCSRF {
			http.Error(w, "Forbidden - CSRF token invalid", http.StatusForbidden)
			return nil, false
		}
		ar := z.requests[f.Get("authRequestID")]
		if ar == nil {
			http.Error(w, "Errors.AuthRequest.NotFound", http.StatusBadRequest)
			return nil, false
		}
		return ar, true
	}
	hidden := func(ar *zitadelAuthRequest) string {
		return `<input type="hidden" name="gorilla.csrf.Token" value="` + zitadelCSRF + `">
<input type="hidden" name="authRequestID" value="` + ar.id + `" />`
	}
	loginPage := func(ar *zitadelAuthRequest) {
		z.page(w, `<html><body><form action="/ui/login/loginname" method="POST">`+hidden(ar)+`
<input class="lgn-input" type="text" id="loginName" name="loginName" value="" autocomplete="username" autofocus required>
<button class="lgn-raised-button" id="submit-button" type="submit">Next</button>
</form></body></html>`)
	}
	switch r.URL.Path {
	case "/oauth/v2/authorize":
		a, p := z.app(f.Get("client_id"))
		if a == nil {
			http.Error(w, "invalid_client", http.StatusBadRequest)
			return
		}
		uris, _ := a.Config["redirectUris"].([]any)
		if !slices.Contains(uris, any(f.Get("redirect_uri"))) || f.Get("response_type") != "code" ||
			!strings.Contains(" "+f.Get("scope")+" ", " openid ") {
			http.Error(w, "invalid_request", http.StatusBadRequest)
			return
		}
		if a.Config["authMethodType"] == "OIDC_AUTH_METHOD_TYPE_NONE" && (f.Get("code_challenge") == "" || f.Get("code_challenge_method") != "S256") {
			http.Error(w, "invalid_request: code_challenge required", http.StatusBadRequest)
			return
		}
		ar := &zitadelAuthRequest{id: "V2_" + z.id(), clientID: a.ClientID, redirect: f.Get("redirect_uri"), state: f.Get("state"),
			challenge: f.Get("code_challenge"), project: p}
		z.requests[ar.id] = ar
		http.SetCookie(w, &http.Cookie{Name: "zitadel.useragent", Value: "agent-" + ar.id, HttpOnly: true})
		http.Redirect(w, r, "/ui/login/login?authRequestID="+ar.id, http.StatusFound)
	case "/ui/login/login":
		ar := z.requests[f.Get("authRequestID")]
		if ar == nil {
			http.Error(w, "Errors.AuthRequest.NotFound", http.StatusBadRequest)
			return
		}
		loginPage(ar)
	case "/ui/login/loginname":
		ar, ok := form()
		if !ok {
			return
		}
		for _, u := range z.users {
			if u.Username == f.Get("loginName") {
				ar.user = u
			}
		}
		// Unknown names are not told apart from known ones
		// (IgnoreUnknownUsernames): the password page follows either way.
		z.page(w, `<html><body><form action="/ui/login/password" method="POST">`+hidden(ar)+`
<input type="text" name="loginName" value="`+html.EscapeString(f.Get("loginName"))+`" autocomplete="username" class="hidden" />
<input class="lgn-input" type="password" id="password" name="password" autocomplete="current-password" autofocus required>
<a class="lgn-icon-button" href="/ui/login/loginname/change?authRequestID=`+ar.id+`">back</a>
<button id="submit-button" class="lgn-raised-button lgn-primary right" type="submit">Next</button>
</form></body></html>`)
	case "/ui/login/password":
		ar, ok := form()
		if !ok {
			return
		}
		if ar.user == nil || f.Get("password") != ar.user.Password || ar.user.PasswordChangeRequired || !ar.user.EmailVerified {
			z.page(w, `<html><body><div class="lgn-error">Password is invalid</div><form action="/ui/login/password" method="POST">`+hidden(ar)+`
<input type="password" name="password"></form></body></html>`)
			return
		}
		http.Redirect(w, r, "/oauth/v2/authorize/callback?id="+ar.id, http.StatusFound)
	case "/oauth/v2/authorize/callback":
		ar := z.requests[f.Get("id")]
		if ar == nil || ar.user == nil {
			http.Error(w, "Errors.AuthRequest.NotFound", http.StatusBadRequest)
			return
		}
		delete(z.requests, ar.id)
		code := "code-" + z.id()
		z.codes[code] = ar
		to, _ := url.Parse(ar.redirect)
		q := to.Query()
		q.Set("code", code)
		q.Set("state", ar.state)
		to.RawQuery = q.Encode()
		http.Redirect(w, r, to.String(), http.StatusFound)
	case "/oauth/v2/token":
		ar := z.codes[f.Get("code")]
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if r.Method != http.MethodPost || ar == nil || f.Get("grant_type") != "authorization_code" || f.Get("client_id") != ar.clientID ||
			f.Get("redirect_uri") != ar.redirect || base64.RawURLEncoding.EncodeToString(sum[:]) != ar.challenge {
			reply(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		delete(z.codes, f.Get("code"))
		z.SignIns++
		iss := z.Issuer
		if iss == "" {
			iss = "http://" + r.Host
		}
		claims := map[string]any{"iss": iss, "sub": ar.user.ID, "aud": []string{ar.clientID, ar.project.ID},
			"email": ar.user.Email, "email_verified": true, "preferred_username": ar.user.Username}
		a, _ := z.app(ar.clientID)
		if keys := ar.user.Grants[ar.project.ID]; ar.project.ProjectRoleAssertion && a.Config["idTokenRoleAssertion"] == true && len(keys) > 0 {
			roles := map[string]any{}
			for _, k := range keys {
				roles[k] = map[string]string{ZitadelOrgID: "bench.localhost"}
			}
			claims["urn:zitadel:iam:org:project:roles"] = roles
		}
		enc := func(v any) string {
			b, _ := json.Marshal(v)
			return base64.RawURLEncoding.EncodeToString(b)
		}
		reply(w, http.StatusOK, map[string]any{"access_token": "at-" + z.id(), "token_type": "Bearer", "expires_in": 43199,
			"id_token": enc(map[string]string{"alg": "RS256", "kid": "k1"}) + "." + enc(claims) + ".c2lnbmF0dXJl"})
	default:
		http.NotFound(w, r)
	}
}
