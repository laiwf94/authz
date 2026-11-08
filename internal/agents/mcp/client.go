package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laiwf94/authz/internal/agents/jsonrpc"
	"github.com/laiwf94/authz/internal/platform/logging"
)

// Client errors.
var (
	ErrResponseTooLarge = errors.New("mcp: upstream response is larger than the limit")
	ErrInputRequired    = errors.New("mcp: upstream asked for interactive input, which is not relayed")
	ErrProtocol         = errors.New("mcp: upstream broke the protocol")
)

// RPCError is a JSON-RPC error returned by the upstream.
type RPCError struct {
	Status int
	Err    *jsonrpc.Error
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("mcp: upstream error %d (HTTP %d): %s", e.Err.Code, e.Status, e.Err.Message)
}

// ClientConfig configures a Client.
type ClientConfig struct {
	URL              string
	Header           http.Header // added to every request, e.g. the upstream credential
	HTTP             *http.Client
	MaxResponseBytes int64
	MaxPages         int // tools/list pages followed
	Info             Implementation
}

type era int

const (
	eraUnknown era = iota
	eraModern
	eraLegacy
)

// Client talks to one upstream MCP server. It is safe for concurrent use.
//
// It speaks the modern protocol first. If the server answers with an HTTP
// error that carries no recognized modern JSON-RPC error, it is a legacy
// server: the client runs the initialize handshake, keeps the session ID,
// and re-initializes once when the server reports the session gone (404).
type Client struct {
	cfg    ClientConfig
	nextID atomic.Int64

	mu      sync.Mutex // guards era, session and version
	era     era
	session string
	version string
}

// NewClient returns a client. cfg.HTTP must not follow redirects; see
// NoRedirects.
func NewClient(cfg ClientConfig) *Client {
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 1 << 20
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = 20
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{CheckRedirect: NoRedirects}
	}
	return &Client{cfg: cfg}
}

// NoRedirects is a CheckRedirect function that refuses every redirect. A
// gateway attaches upstream credentials to its requests; following a redirect
// would send them wherever the upstream points.
func NoRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// ListTools returns every tool the upstream offers, following pagination.
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	var all []Tool
	cursor := ""
	for page := 0; page < c.cfg.MaxPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := c.call(ctx, MethodToolsList, params, "", nil)
		if err != nil {
			return nil, err
		}
		var res struct {
			Tools      []Tool `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("%w: tools/list result: %v", ErrProtocol, err)
		}
		all = append(all, res.Tools...)
		if res.NextCursor == "" {
			return all, nil
		}
		cursor = res.NextCursor
	}
	return nil, fmt.Errorf("%w: tools/list has more than %d pages", ErrProtocol, c.cfg.MaxPages)
}

// CallTool calls a tool and returns its decoded result object. paramHeaders
// are the Mcp-Param-* headers for the tool's x-mcp-header arguments.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any, paramHeaders http.Header) (map[string]any, error) {
	raw, err := c.call(ctx, MethodToolsCall, map[string]any{"name": name, "arguments": args}, name, paramHeaders)
	if err != nil {
		return nil, err
	}
	v, err := jsonrpc.DecodeValue(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: tools/call result: %v", ErrProtocol, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: tools/call result is not an object", ErrProtocol)
	}
	return m, nil
}

func (c *Client) state() (era, string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.era, c.session, c.version
}

// call sends one request, choosing the era and recovering a lost session.
// The legacy era is remembered only after an initialize handshake succeeds,
// so one ambiguous error (a proxy's HTML 404) cannot pin a modern server to
// the wrong era; a failed handshake later makes the next call probe again.
func (c *Client) call(ctx context.Context, method string, params map[string]any, name string, extra http.Header) (json.RawMessage, error) {
	e, _, _ := c.state()
	var modernErr error
	if e != eraLegacy {
		res, status, err := c.modern(ctx, method, params, name, extra)
		if err == nil || e == eraModern || !legacyFallback(status, err) {
			if err == nil && e == eraUnknown {
				c.mu.Lock()
				c.era = eraModern
				c.mu.Unlock()
			}
			return res, err
		}
		modernErr = err
	}
	for attempt := 0; ; attempt++ {
		sess, version, err := c.startSession(ctx)
		if err != nil {
			if modernErr != nil {
				return nil, fmt.Errorf("%w (and the legacy handshake failed: %w)", modernErr, err)
			}
			return nil, err
		}
		res, status, err := c.legacy(ctx, method, params, sess, version)
		if status == http.StatusNotFound && sess != "" && attempt == 0 {
			c.resetSession(sess)
			continue
		}
		return res, err
	}
}

// legacyFallback decides whether a failed modern request means the server
// is a legacy one: an HTTP 400, 404 or 405 without a recognized modern
// JSON-RPC error in the body.
func legacyFallback(status int, err error) bool {
	if status != http.StatusBadRequest && status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
		return false
	}
	var re *RPCError
	if !errors.As(err, &re) {
		return true
	}
	switch re.Err.Code {
	case CodeHeaderMismatch, CodeMissingRequiredCapability, CodeUnsupportedProtocolVersion:
		return false
	case jsonrpc.CodeMethodNotFound:
		return status != http.StatusNotFound
	}
	return true
}

func (c *Client) modern(ctx context.Context, method string, params map[string]any, name string, extra http.Header) (json.RawMessage, int, error) {
	p := make(map[string]any, len(params)+1)
	for k, v := range params {
		p[k] = v
	}
	p["_meta"] = map[string]any{MetaProtocolVersion: VersionModern, MetaClientInfo: c.cfg.Info, MetaClientCapabilities: map[string]any{}}
	h := http.Header{}
	h.Set(HeaderProtocolVersion, VersionModern)
	h.Set(HeaderMethod, method)
	if name != "" {
		h.Set(HeaderName, EncodeHeaderValue(name))
	}
	for k, vs := range extra {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	res, status, _, err := c.post(ctx, method, p, h)
	if err != nil {
		return nil, status, err
	}
	var rt struct {
		ResultType string `json:"resultType"`
	}
	if err := json.Unmarshal(res, &rt); err != nil {
		return nil, status, fmt.Errorf("%w: result is not an object", ErrProtocol)
	}
	switch rt.ResultType {
	case "", "complete":
		return res, status, nil
	case "input_required":
		return nil, status, ErrInputRequired
	default:
		return nil, status, fmt.Errorf("%w: unknown resultType %q", ErrProtocol, rt.ResultType)
	}
}

func (c *Client) legacy(ctx context.Context, method string, params map[string]any, sess, version string) (json.RawMessage, int, error) {
	h := http.Header{}
	h.Set(HeaderProtocolVersion, version)
	if sess != "" {
		h.Set(HeaderSessionID, sess)
	}
	res, status, _, err := c.post(ctx, method, params, h)
	return res, status, err
}

func (c *Client) resetSession(old string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == old {
		c.session, c.version = "", ""
	}
}

// startSession runs the initialize handshake once per session. If the
// handshake fails, the era is forgotten so the next call probes again
// (perhaps the server is no longer a legacy one).
func (c *Client) startSession(ctx context.Context) (sess, version string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if err != nil {
			c.era = eraUnknown
		}
	}()
	if c.version != "" {
		return c.session, c.version, nil
	}
	params := map[string]any{"protocolVersion": Version251125, "capabilities": map[string]any{}, "clientInfo": c.cfg.Info}
	res, _, hdr, err := c.post(ctx, MethodInitialize, params, http.Header{})
	if err != nil {
		return "", "", fmt.Errorf("initialize: %w", err)
	}
	var ir struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(res, &ir); err != nil || !IsLegacy(ir.ProtocolVersion) {
		return "", "", fmt.Errorf("%w: initialize answered with unsupported version %q", ErrProtocol, ir.ProtocolVersion)
	}
	sess = hdr.Get(HeaderSessionID)
	for i := 0; i < len(sess); i++ {
		if sess[i] < 0x21 || sess[i] > 0x7e {
			return "", "", fmt.Errorf("%w: session id has invalid characters", ErrProtocol)
		}
	}
	h := http.Header{}
	h.Set(HeaderProtocolVersion, ir.ProtocolVersion)
	if sess != "" {
		h.Set(HeaderSessionID, sess)
	}
	if err := c.notify(ctx, MethodInitialized, h); err != nil {
		return "", "", fmt.Errorf("initialized: %w", err)
	}
	c.session, c.version, c.era = sess, ir.ProtocolVersion, eraLegacy
	return sess, ir.ProtocolVersion, nil
}

func (c *Client) newRequest(ctx context.Context, body []byte, h http.Header) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", c.cfg.Info.Name+"/"+c.cfg.Info.Version)
	for k, vs := range c.cfg.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for k, vs := range h {
		req.Header[k] = vs
	}
	// The calling request's correlation ID goes upstream as the trace ID
	// of a traceparent, replacing any configured one.
	logging.Propagate(ctx, req.Header)
	return req, nil
}

func (c *Client) notify(ctx context.Context, method string, h http.Header) error {
	body, _ := jsonrpc.Marshal(jsonrpc.Request{JSONRPC: jsonrpc.Version, Method: method})
	req, err := c.newRequest(ctx, body, h)
	if err != nil {
		return err
	}
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("upstream answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// post sends a request and returns the result, the HTTP status and headers.
func (c *Client) post(ctx context.Context, method string, params map[string]any, h http.Header) (json.RawMessage, int, http.Header, error) {
	id := json.RawMessage(strconv.FormatInt(c.nextID.Add(1), 10))
	body, err := jsonrpc.Marshal(jsonrpc.Request{JSONRPC: jsonrpc.Version, ID: id, Method: method, Params: params})
	if err != nil {
		return nil, 0, nil, err
	}
	req, err := c.newRequest(ctx, body, h)
	if err != nil {
		return nil, 0, nil, err
	}
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1)
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	var msg *jsonrpc.Message
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("%w: upstream redirected (HTTP %d); redirects are not followed", ErrProtocol, resp.StatusCode)
	case ct == "text/event-stream" && resp.StatusCode == http.StatusOK:
		msg, err = readSSE(limited, id, c.cfg.MaxResponseBytes)
	default:
		data, rerr := io.ReadAll(limited)
		if rerr != nil {
			return nil, resp.StatusCode, resp.Header, rerr
		}
		if int64(len(data)) > c.cfg.MaxResponseBytes {
			return nil, resp.StatusCode, resp.Header, ErrResponseTooLarge
		}
		var derr *jsonrpc.Error
		msg, _, derr = jsonrpc.Decode(data)
		if derr != nil {
			if resp.StatusCode != http.StatusOK {
				return nil, resp.StatusCode, resp.Header, fmt.Errorf("upstream answered HTTP %d", resp.StatusCode)
			}
			return nil, resp.StatusCode, resp.Header, fmt.Errorf("%w: %s", ErrProtocol, derr.Message)
		}
	}
	if err != nil {
		return nil, resp.StatusCode, resp.Header, err
	}
	if msg.Kind != jsonrpc.KindResponse {
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("%w: expected a response", ErrProtocol)
	}
	// An error may come without an id (when the server could not read ours);
	// any id it does carry must be ours.
	if msg.ID != nil && !bytes.Equal(msg.ID, id) {
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("%w: response id %s does not match request id %s", ErrProtocol, msg.ID, id)
	}
	if msg.Error != nil {
		return nil, resp.StatusCode, resp.Header, &RPCError{Status: resp.StatusCode, Err: msg.Error}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("%w: result with HTTP %d", ErrProtocol, resp.StatusCode)
	}
	return msg.Result, resp.StatusCode, resp.Header, nil
}

// readSSE reads an event stream until the response to id arrives.
// Notifications and server requests on the stream are skipped.
func readSSE(r io.Reader, id json.RawMessage, limit int64) (*jsonrpc.Message, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), int(limit)+1)
	var data strings.Builder
	var total int64
	dispatch := func() (*jsonrpc.Message, bool) {
		defer data.Reset()
		if data.Len() == 0 {
			return nil, false
		}
		msg, _, err := jsonrpc.Decode([]byte(data.String()))
		if err != nil || msg.Kind != jsonrpc.KindResponse || !bytes.Equal(msg.ID, id) {
			return nil, false
		}
		return msg, true
	}
	for sc.Scan() {
		line := sc.Text()
		total += int64(len(line)) + 1
		if total > limit {
			return nil, ErrResponseTooLarge
		}
		switch {
		case line == "":
			if msg, ok := dispatch(); ok {
				return msg, nil
			}
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, ErrResponseTooLarge
		}
		return nil, err
	}
	if msg, ok := dispatch(); ok {
		return msg, nil
	}
	return nil, fmt.Errorf("%w: event stream ended without a response", ErrProtocol)
}

// IsTimeout reports whether err is a deadline or network timeout.
func IsTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne interface{ Timeout() bool }
	return errors.As(err, &ne) && ne.Timeout()
}

// DefaultDialTimeout bounds connection setup to upstreams.
const DefaultDialTimeout = 5 * time.Second
