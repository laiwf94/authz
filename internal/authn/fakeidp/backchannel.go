package fakeidp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Back-channel logout (OpenID Connect Back-Channel Logout 1.0): every login
// starts a provider session with its own sid, carried in the ID tokens of
// the login and of every refresh. Logout ends a user's provider sessions
// and tells each client that registered a BackchannelLogoutURI, as a real
// provider does when a user signs out there or an administrator disables
// them.

// LogoutTokenTTL is how long a logout token the IdP mints is valid.
const LogoutTokenTTL = 2 * time.Minute

// LogoutToken mints a logout token for client naming sub, sid or both
// (either may be ""), typed logout+jwt as section 2.4 recommends.
func (i *IdP) LogoutToken(client, sub, sid string) (string, error) {
	now := i.cfg.Now()
	claims := map[string]any{
		"iss": i.cfg.Issuer, "aud": client, "iat": now.Unix(), "exp": now.Add(LogoutTokenTTL).Unix(),
		"jti":    randomString(),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	if sub != "" {
		claims["sub"] = sub
	}
	if sid != "" {
		claims["sid"] = sid
	}
	return i.SignJWTType("logout+jwt", claims)
}

// SetBackchannelClient replaces Config.BackchannelClient, for a test whose
// relying party starts after the IdP.
func (i *IdP) SetBackchannelClient(c *http.Client) {
	i.mu.Lock()
	i.cfg.BackchannelClient = c
	i.mu.Unlock()
}

// Sessions returns the sids of a user's live provider sessions, sorted.
func (i *IdP) Sessions(username string) []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	var out []string
	for sid, g := range i.sessions {
		if g.user.Username == username {
			out = append(out, sid)
		}
	}
	sort.Strings(out)
	return out
}

// Logout ends every provider session of a user, revokes their refresh
// tokens (as EndSessions does) and posts a logout token naming sub and sid
// to each client with a BackchannelLogoutURI. It returns how many logout
// requests the clients answered with 200, and the first failure.
func (i *IdP) Logout(ctx context.Context, username string) (int, error) {
	i.EndSessions(username)
	i.mu.Lock()
	var ended []*grant
	for sid, g := range i.sessions {
		if g.user.Username == username {
			ended = append(ended, g)
			delete(i.sessions, sid)
		}
	}
	i.mu.Unlock()
	sort.Slice(ended, func(a, b int) bool { return ended[a].sid < ended[b].sid })
	i.mu.Lock()
	hc := i.cfg.BackchannelClient
	i.mu.Unlock()
	if hc == nil {
		hc = http.DefaultClient
	}
	sent := 0
	var first error
	for _, g := range ended {
		c := i.client(g.client)
		if c == nil || c.BackchannelLogoutURI == "" {
			continue
		}
		err := i.postLogout(ctx, hc, c, g.user.Username, g.sid)
		if err == nil {
			sent++
		} else if first == nil {
			first = err
		}
	}
	return sent, first
}

func (i *IdP) postLogout(ctx context.Context, hc *http.Client, c *Client, sub, sid string) error {
	tok, err := i.LogoutToken(c.ID, sub, sid)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BackchannelLogoutURI,
		strings.NewReader(url.Values{"logout_token": {tok}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("fakeidp: back-channel logout to %s: %w", c.ID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fakeidp: back-channel logout to %s: status %d: %s", c.ID, resp.StatusCode, body)
	}
	return nil
}
