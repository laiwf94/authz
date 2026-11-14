package fakeidp

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"sort"
)

// Refresh tokens: every code exchange issues one, and every refresh rotates
// it (the old token stops working), as providers that guard against token
// theft do. EndSessions and SetTokenEndpointDown let tests and the demo make
// the provider refuse a user or fail altogether.

func (i *IdP) issueRefresh(client string, u *User) string {
	t := randomString()
	i.mu.Lock()
	i.refreshes[t] = &grant{client: client, user: u}
	i.mu.Unlock()
	return t
}

func (i *IdP) refreshGrant(w http.ResponseWriter, clientID, token string) {
	i.mu.Lock()
	g := i.refreshes[token]
	delete(i.refreshes, token) // single use: rotated below
	i.mu.Unlock()
	if g == nil || g.client != clientID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid, revoked, or for another client")
		return
	}
	access := randomString()
	now := i.cfg.Now()
	i.mu.Lock()
	i.tokens[access] = &grant{client: clientID, user: g.user, expires: now.Add(tokenTTL)}
	i.mu.Unlock()
	atHash := sha256.Sum256([]byte(access))
	// Core 12.2: same iss and sub, no nonce (this answers no login request).
	idToken, err := i.SignJWT(map[string]any{
		"iss": i.cfg.Issuer, "sub": g.user.Username, "aud": clientID, "exp": now.Add(tokenTTL).Unix(),
		"iat": now.Unix(), "email": g.user.Email, "email_verified": true, "name": g.user.Name, "groups": g.user.Groups,
		"at_hash": base64.RawURLEncoding.EncodeToString(atHash[:16]),
	})
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "signing failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer",
		"expires_in": int(tokenTTL.Seconds()), "id_token": idToken, "refresh_token": i.issueRefresh(clientID, g.user)})
}

// EndSessions revokes every refresh token of a user, as disabling the user
// or ending their sessions at a real provider does, and returns how many.
func (i *IdP) EndSessions(username string) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	n := 0
	for t, g := range i.refreshes {
		if g.user.Username == username {
			delete(i.refreshes, t)
			n++
		}
	}
	return n
}

// RefreshTokens returns a user's live refresh tokens, so a test can check
// that none of them is stored or logged in the clear.
func (i *IdP) RefreshTokens(username string) []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	var out []string
	for t, g := range i.refreshes {
		if g.user.Username == username {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// SetTokenEndpointDown makes the token endpoint answer 503 (down true) or
// work again, to stand for a provider outage.
func (i *IdP) SetTokenEndpointDown(down bool) {
	i.mu.Lock()
	i.down = down
	i.mu.Unlock()
}

func (i *IdP) tokenDown() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.down
}
