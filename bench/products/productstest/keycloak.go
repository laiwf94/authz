package productstest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Keycloak is a fake of the parts of Keycloak's admin REST API that
// bench/products uses: the master realm's admin-cli password grant, a
// realm with its clients, and partial imports of groups and users. It
// refuses what Keycloak 26 refuses (an expired or missing token, a realm
// or client that exists, a group without its path, a user in a group
// that does not exist), and fields it does not know, so a typo in a
// representation fails a test instead of being dropped.
type Keycloak struct {
	AdminUser, AdminPassword string
	// TokenLife is the admin token's expires_in in seconds (default 60,
	// admin-cli's).
	TokenLife int

	mu      sync.Mutex
	fail    func(r *http.Request) int
	tokens  map[string]bool
	signIns int
	realms  map[string]*KeycloakRealm
	ids     int
}

// KeycloakRealm is what the fake holds for one realm.
type KeycloakRealm struct {
	Settings map[string]any
	Clients  map[string]map[string]any // by clientId
	Groups   map[string]string         // name -> id
	Users    map[string]*KeycloakUser  // by username
	Imports  int
}

// KeycloakUser is an imported user.
type KeycloakUser struct {
	ID, Username, Email, FirstName, LastName string
	Enabled, EmailVerified                   bool
	Groups                                   []string // names
	Password                                 string
}

// Realm returns a copy of the named realm's state, or nil.
func (k *Keycloak) Realm(name string) *KeycloakRealm {
	k.mu.Lock()
	defer k.mu.Unlock()
	r := k.realms[name]
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

// SetFail makes fn see each request first: a status other than 0 is
// answered instead of the fake's. nil clears it.
func (k *Keycloak) SetFail(fn func(r *http.Request) int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.fail = fn
}

// SignIns is how often the admin signed in.
func (k *Keycloak) SignIns() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.signIns
}

// Expire makes every admin token issued so far invalid, as a token's
// lifetime running out does.
func (k *Keycloak) Expire() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.tokens = nil
}

// keycloakGroupRep, keycloakUserRep and keycloakImport are the fields the
// fake takes; anything else is refused.
type keycloakGroupRep struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type keycloakUserRep struct {
	Username      string   `json:"username"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"emailVerified"`
	FirstName     string   `json:"firstName"`
	LastName      string   `json:"lastName"`
	Enabled       bool     `json:"enabled"`
	Groups        []string `json:"groups"`
	Credentials   []struct {
		Type      string `json:"type"`
		Value     string `json:"value"`
		Temporary bool   `json:"temporary"`
	} `json:"credentials"`
}

type keycloakImport struct {
	IfResourceExists string             `json:"ifResourceExists"`
	Groups           []keycloakGroupRep `json:"groups"`
	Users            []keycloakUserRep  `json:"users"`
}

type keycloakClientRep struct {
	ClientID                  string            `json:"clientId"`
	Enabled                   bool              `json:"enabled"`
	Protocol                  string            `json:"protocol"`
	PublicClient              bool              `json:"publicClient"`
	Secret                    string            `json:"secret"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled"`
	RedirectURIs              []string          `json:"redirectUris"`
	Attributes                map[string]string `json:"attributes"`
	ProtocolMappers           []struct {
		Name           string            `json:"name"`
		Protocol       string            `json:"protocol"`
		ProtocolMapper string            `json:"protocolMapper"`
		Config         map[string]string `json:"config"`
	} `json:"protocolMappers"`
}

type keycloakRealmRep struct {
	Realm               string              `json:"realm"`
	Enabled             bool                `json:"enabled"`
	BruteForceProtected bool                `json:"bruteForceProtected"`
	Clients             []keycloakClientRep `json:"clients"`
}

func (k *Keycloak) id() string {
	k.ids++
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", k.ids)
}

func clientMap(c keycloakClientRep) map[string]any {
	b, _ := json.Marshal(c)
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

// ServeHTTP implements http.Handler.
func (k *Keycloak) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail != nil {
		if code := k.fail(r); code != 0 {
			reply(w, code, map[string]string{"error": "unknown_error"})
			return
		}
	}
	if r.URL.Path == "/realms/master/protocol/openid-connect/token" && r.Method == http.MethodPost {
		r.ParseForm()
		f := r.PostForm
		if f.Get("grant_type") != "password" || f.Get("client_id") != "admin-cli" ||
			f.Get("username") != k.AdminUser || f.Get("password") != k.AdminPassword {
			reply(w, http.StatusUnauthorized, map[string]string{"error": "invalid_grant"})
			return
		}
		k.signIns++
		tok := "admin-token-" + strconv.Itoa(k.signIns)
		if k.tokens == nil {
			k.tokens = map[string]bool{}
		}
		k.tokens[tok] = true
		life := k.TokenLife
		if life == 0 {
			life = 60
		}
		reply(w, http.StatusOK, map[string]any{"access_token": tok, "expires_in": life, "token_type": "Bearer"})
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/admin/realms")
	if !ok {
		http.NotFound(w, r)
		return
	}
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !k.tokens[tok] {
		reply(w, http.StatusUnauthorized, map[string]string{"error": "HTTP 401 Unauthorized"})
		return
	}
	if r.ContentLength != 0 && r.Header.Get("Content-Type") != "application/json" {
		reply(w, http.StatusUnsupportedMediaType, map[string]string{"error": "content type"})
		return
	}
	if k.realms == nil {
		k.realms = map[string]*KeycloakRealm{}
	}
	parts := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	if rest == "" {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var rep keycloakRealmRep
		if !decode(w, r, &rep) {
			return
		}
		if k.realms[rep.Realm] != nil {
			reply(w, http.StatusConflict, map[string]string{"errorMessage": "Conflict detected. See logs for details"})
			return
		}
		realm := &KeycloakRealm{Settings: map[string]any{"enabled": rep.Enabled, "bruteForceProtected": rep.BruteForceProtected},
			Clients: map[string]map[string]any{}, Groups: map[string]string{}, Users: map[string]*KeycloakUser{}}
		for _, c := range rep.Clients {
			m := clientMap(c)
			m["id"] = k.id()
			realm.Clients[c.ClientID] = m
		}
		k.realms[rep.Realm] = realm
		w.WriteHeader(http.StatusCreated)
		return
	}
	realm := k.realms[parts[0]]
	if realm == nil {
		reply(w, http.StatusNotFound, map[string]string{"error": "Realm not found."})
		return
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		reply(w, http.StatusOK, map[string]any{"realm": parts[0], "enabled": realm.Settings["enabled"]})
	case len(parts) == 1 && r.Method == http.MethodPut:
		var rep keycloakRealmRep
		if !decode(w, r, &rep) {
			return
		}
		realm.Settings = map[string]any{"enabled": rep.Enabled, "bruteForceProtected": rep.BruteForceProtected}
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 2 && parts[1] == "clients" && r.Method == http.MethodGet:
		out := []map[string]any{}
		if c := realm.Clients[r.URL.Query().Get("clientId")]; c != nil {
			out = append(out, c)
		}
		reply(w, http.StatusOK, out)
	case len(parts) == 2 && parts[1] == "clients" && r.Method == http.MethodPost:
		var rep keycloakClientRep
		if !decode(w, r, &rep) {
			return
		}
		if realm.Clients[rep.ClientID] != nil {
			reply(w, http.StatusConflict, map[string]string{"errorMessage": "Client " + rep.ClientID + " already exists"})
			return
		}
		m := clientMap(rep)
		m["id"] = k.id()
		realm.Clients[rep.ClientID] = m
		w.WriteHeader(http.StatusCreated)
	case len(parts) == 3 && parts[1] == "clients" && r.Method == http.MethodPut:
		var rep keycloakClientRep
		if !decode(w, r, &rep) {
			return
		}
		for name, c := range realm.Clients {
			if c["id"] == parts[2] {
				m := clientMap(rep)
				m["id"] = parts[2]
				// A PUT keeps the client's mappers, as Keycloak's does.
				m["protocolMappers"] = c["protocolMappers"]
				delete(realm.Clients, name)
				realm.Clients[rep.ClientID] = m
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		reply(w, http.StatusNotFound, map[string]string{"error": "Could not find client"})
	case len(parts) == 2 && parts[1] == "partialImport" && r.Method == http.MethodPost:
		var rep keycloakImport
		if !decode(w, r, &rep) {
			return
		}
		k.partialImport(w, realm, rep)
	case len(parts) == 2 && parts[1] == "users" && r.Method == http.MethodGet:
		q := r.URL.Query()
		out := []map[string]any{}
		if u := realm.Users[q.Get("username")]; u != nil && q.Get("exact") == "true" {
			out = append(out, map[string]any{"id": u.ID, "username": u.Username, "email": u.Email, "enabled": u.Enabled})
		}
		reply(w, http.StatusOK, out)
	case len(parts) == 4 && parts[1] == "users" && parts[3] == "groups" && r.Method == http.MethodGet:
		for _, u := range realm.Users {
			if u.ID == parts[2] {
				out := []map[string]string{}
				for _, g := range u.Groups {
					out = append(out, map[string]string{"id": realm.Groups[g], "name": g, "path": "/" + g})
				}
				reply(w, http.StatusOK, out)
				return
			}
		}
		reply(w, http.StatusNotFound, map[string]string{"error": "User not found"})
	default:
		http.NotFound(w, r)
	}
}

func (k *Keycloak) partialImport(w http.ResponseWriter, realm *KeycloakRealm, rep keycloakImport) {
	if rep.IfResourceExists != "SKIP" {
		reply(w, http.StatusBadRequest, map[string]string{"error": "ifResourceExists"})
		return
	}
	type result struct {
		Action, ResourceType, ResourceName, ID string
	}
	var results []result
	var added, skipped int
	// Validate everything first: a partial import is one transaction.
	for _, g := range rep.Groups {
		if g.Path != "/"+g.Name {
			// What Keycloak 26 does: a NullPointerException, answered 500.
			reply(w, http.StatusInternalServerError, map[string]string{"error": "unknown_error"})
			return
		}
	}
	groups := map[string]bool{}
	for _, g := range rep.Groups {
		groups[g.Name] = true
	}
	for _, u := range rep.Users {
		if u.Username == "" || len(u.Credentials) != 1 || u.Credentials[0].Type != "password" || u.Credentials[0].Value == "" {
			reply(w, http.StatusBadRequest, map[string]string{"errorMessage": "user " + u.Username + ": want one password credential"})
			return
		}
		for _, p := range u.Groups {
			name := strings.TrimPrefix(p, "/")
			if realm.Groups[name] == "" && !groups[name] {
				reply(w, http.StatusBadRequest, map[string]string{"errorMessage": "Unable to find group specified by path: " + p})
				return
			}
		}
	}
	for _, g := range rep.Groups {
		if id := realm.Groups[g.Name]; id != "" {
			skipped++
			results = append(results, result{"SKIPPED", "GROUP", g.Name, id})
			continue
		}
		realm.Groups[g.Name] = k.id()
		added++
		results = append(results, result{"ADDED", "GROUP", g.Name, realm.Groups[g.Name]})
	}
	for _, u := range rep.Users {
		if old := realm.Users[u.Username]; old != nil {
			skipped++
			results = append(results, result{"SKIPPED", "USER", u.Username, old.ID})
			continue
		}
		names := make([]string, len(u.Groups))
		for i, p := range u.Groups {
			names[i] = strings.TrimPrefix(p, "/")
		}
		sort.Strings(names)
		nu := &KeycloakUser{ID: k.id(), Username: u.Username, Email: u.Email, FirstName: u.FirstName, LastName: u.LastName,
			Enabled: u.Enabled, EmailVerified: u.EmailVerified, Groups: names, Password: u.Credentials[0].Value}
		realm.Users[u.Username] = nu
		added++
		results = append(results, result{"ADDED", "USER", u.Username, nu.ID})
	}
	realm.Imports++
	reply(w, http.StatusOK, map[string]any{"added": added, "skipped": skipped, "overwritten": 0, "results": results})
}
