package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Limits on what identity providers send back.
const (
	maxResponseBytes = 1 << 20
	requestTimeout   = 10 * time.Second
)

// Error is a failed login step. Reason is a stable code for audit logs.
type Error struct {
	Reason string
	Err    error
}

func (e *Error) Error() string { return "oidc: " + e.Reason + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(reason string, format string, args ...any) error {
	return &Error{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// Reason codes.
const (
	ReasonDiscovery     = "discovery_failed"
	ReasonJWKS          = "jwks_failed"
	ReasonTokenExchange = "token_exchange_failed"
	ReasonIDToken       = "id_token_invalid"
	ReasonNonce         = "nonce_mismatch"
	ReasonUserinfo      = "userinfo_failed"
	ReasonUnknownKey    = "unknown_signing_key"
	ReasonClaims        = "claims_invalid"
	// ReasonRefreshRefused is a refresh the provider answered with
	// invalid_grant: the user's sign-in there has ended.
	ReasonRefreshRefused = "refresh_refused"
	// ReasonRefreshFailed is a refresh that got no answer about the user.
	ReasonRefreshFailed = "refresh_failed"
)

// NewHTTPClient returns the client used for back-channel calls: bounded
// time, and redirects refused so a credential is never forwarded to a host
// other than the one it was meant for.
func NewHTTPClient(base *http.Transport) *http.Client {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport).Clone()
	}
	return &http.Client{
		Transport: base,
		Timeout:   requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not followed")
		},
	}
}

// do performs req and returns the body when the status is 200 and
// the body is within limits. maxAge is the Cache-Control max-age, or -1.
func do(client *http.Client, req *http.Request) (body []byte, status int, maxAge time.Duration, err error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, -1, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, -1, err
	}
	// A response that completes after the request's deadline is no answer:
	// the transport can still deliver one the server wrote only because it
	// saw the client give up (#234).
	if cerr := req.Context().Err(); cerr != nil {
		return nil, 0, -1, cerr
	}
	if len(body) > maxResponseBytes {
		return nil, resp.StatusCode, -1, fmt.Errorf("response larger than %d bytes", maxResponseBytes)
	}
	return body, resp.StatusCode, cacheMaxAge(resp.Header.Get("Cache-Control")), nil
}

func get(ctx context.Context, client *http.Client, u string, bearer string) ([]byte, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, -1, err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	body, status, maxAge, err := do(client, req)
	if err != nil {
		return nil, -1, err
	}
	if status != http.StatusOK {
		return nil, -1, fmt.Errorf("GET %s: status %d", redact(u), status)
	}
	return body, maxAge, nil
}

func cacheMaxAge(h string) time.Duration {
	for _, d := range strings.Split(h, ",") {
		d = strings.TrimSpace(strings.ToLower(d))
		if v, ok := strings.CutPrefix(d, "max-age="); ok {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				return time.Duration(n) * time.Second
			}
		}
	}
	return -1
}

// redact drops the query string, which may carry tokens, from logged URLs.
func redact(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return "(invalid URL)"
	}
	p.RawQuery, p.Fragment, p.User = "", "", nil
	return p.String()
}

func requireHTTPS(field, u string) error {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil || p.Fragment != "" {
		return fmt.Errorf("%s %q must be an absolute https URL without user info or fragment", field, u)
	}
	return nil
}
