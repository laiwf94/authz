package fakeidp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	codeTTL  = time.Minute
	tokenTTL = 5 * time.Minute
)

type grant struct {
	client      string
	redirectURI string
	challenge   string
	nonce       string
	user        *User
	expires     time.Time
}

func randomString() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (i *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	iss := i.cfg.Issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"jwks_uri":                              iss + "/jwks",
		"userinfo_endpoint":                     iss + "/userinfo",
		"end_session_endpoint":                  iss + "/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []string{"openid", "email", "profile", "groups"},
	})
}

// KeyID is the kid of the IdP's RSA signing key.
const KeyID = "fakeidp-rsa-1"

func (i *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := i.rsaKey.PublicKey
	w.Header().Set("Cache-Control", "max-age=600")
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KeyID,
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (i *IdP) client(id string) *Client {
	for k := range i.cfg.Clients {
		if i.cfg.Clients[k].ID == id {
			return &i.cfg.Clients[k]
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// checkAuthorize validates an authorization request. Errors that make the
// redirect URI untrustworthy are shown to the user instead of redirected.
func (i *IdP) checkAuthorize(q url.Values) (string, int) {
	c := i.client(q.Get("client_id"))
	if c == nil {
		return "unknown client_id", http.StatusBadRequest
	}
	if !contains(c.RedirectURIs, q.Get("redirect_uri")) {
		return "redirect_uri is not registered for this client", http.StatusBadRequest
	}
	if q.Get("response_type") != "code" {
		return "only response_type=code is supported", http.StatusBadRequest
	}
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 {
		return "PKCE with S256 is required", http.StatusBadRequest
	}
	if !contains(strings.Fields(q.Get("scope")), "openid") {
		return "scope must include openid", http.StatusBadRequest
	}
	if q.Get("nonce") == "" || q.Get("state") == "" {
		return "state and nonce are required", http.StatusBadRequest
	}
	return "", 0
}

var authorizeParams = []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"}

func (i *IdP) authorizeForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if msg, status := i.checkAuthorize(q); status != 0 {
		httpError(w, status, msg)
		return
	}
	hidden := map[string]string{}
	for _, k := range authorizeParams {
		hidden[k] = q.Get(k)
	}
	renderLogin(w, http.StatusOK, loginView{Action: i.cfg.Issuer + "/authorize", Protocol: "OpenID Connect", Hidden: hidden})
}

func (i *IdP) authorizeSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		httpError(w, http.StatusBadRequest, "bad form")
		return
	}
	q := r.PostForm
	if msg, status := i.checkAuthorize(q); status != 0 {
		httpError(w, status, msg)
		return
	}
	u, ok := i.user(q.Get("username"), q.Get("password"))
	if !ok {
		hidden := map[string]string{}
		for _, k := range authorizeParams {
			hidden[k] = q.Get(k)
		}
		renderLogin(w, http.StatusUnauthorized, loginView{Action: i.cfg.Issuer + "/authorize", Protocol: "OpenID Connect",
			Error: "Wrong username or password.", Hidden: hidden})
		return
	}
	code := randomString()
	i.mu.Lock()
	i.codes[code] = &grant{client: q.Get("client_id"), redirectURI: q.Get("redirect_uri"), challenge: q.Get("code_challenge"),
		nonce: q.Get("nonce"), user: u, expires: i.cfg.Now().Add(codeTTL)}
	i.mu.Unlock()
	target, _ := url.Parse(q.Get("redirect_uri"))
	tq := target.Query()
	tq.Set("code", code)
	tq.Set("state", q.Get("state"))
	target.RawQuery = tq.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func tokenError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func (i *IdP) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	f := r.PostForm
	clientID, secret, basic := r.BasicAuth()
	if basic {
		clientID, _ = url.QueryUnescape(clientID)
		secret, _ = url.QueryUnescape(secret)
	} else {
		clientID, secret = f.Get("client_id"), f.Get("client_secret")
	}
	c := i.client(clientID)
	if c == nil || subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) != 1 {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if i.tokenDown() {
		tokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "the token endpoint is down")
		return
	}
	switch f.Get("grant_type") {
	case "authorization_code":
	case "refresh_token":
		i.refreshGrant(w, clientID, f.Get("refresh_token"))
		return
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code and refresh_token")
		return
	}
	i.mu.Lock()
	g := i.codes[f.Get("code")]
	delete(i.codes, f.Get("code")) // single use, even when the rest fails
	i.mu.Unlock()
	if g == nil || !i.cfg.Now().Before(g.expires) || g.client != clientID || g.redirectURI != f.Get("redirect_uri") {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "code is invalid, expired, used, or for another client")
		return
	}
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	access := randomString()
	now := i.cfg.Now()
	i.mu.Lock()
	i.tokens[access] = &grant{client: clientID, user: g.user, expires: now.Add(tokenTTL)}
	i.mu.Unlock()
	atHash := sha256.Sum256([]byte(access))
	idToken, err := i.SignJWT(map[string]any{
		"iss": i.cfg.Issuer, "sub": g.user.Username, "aud": clientID, "exp": now.Add(tokenTTL).Unix(),
		"iat": now.Unix(), "nonce": g.nonce, "email": g.user.Email, "email_verified": true,
		"name": g.user.Name, "groups": g.user.Groups,
		"at_hash": base64.RawURLEncoding.EncodeToString(atHash[:16]),
	})
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "signing failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer",
		"expires_in": int(tokenTTL.Seconds()), "id_token": idToken, "refresh_token": i.issueRefresh(clientID, g.user)})
}

// SignJWT signs claims with the IdP's RSA key (RS256).
func (i *IdP) SignJWT(claims map[string]any) (string, error) {
	hb, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": KeyID, "typ": "JWT"})
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.rsaKey, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (i *IdP) userinfo(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	i.mu.Lock()
	g := i.tokens[tok]
	i.mu.Unlock()
	if !ok || g == nil || !i.cfg.Now().Before(g.expires) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		tokenError(w, http.StatusUnauthorized, "invalid_token", "unknown or expired access token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sub": g.user.Username, "email": g.user.Email,
		"email_verified": true, "name": g.user.Name, "groups": g.user.Groups})
}

func (i *IdP) endSession(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c := i.client(q.Get("client_id"))
	if target := q.Get("post_logout_redirect_uri"); target != "" {
		if c == nil || !contains(c.PostLogoutRedirectURIs, target) {
			httpError(w, http.StatusBadRequest, "post_logout_redirect_uri is not registered")
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("Signed out of fakeidp.\n"))
}
