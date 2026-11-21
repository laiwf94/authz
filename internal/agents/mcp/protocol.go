// Package mcp implements the parts of the Model Context Protocol a tool
// gateway needs, over the Streamable HTTP transport: a server that agents
// talk to and a client for upstream servers.
//
// Two protocol eras are supported, as the specification allows for
// "dual-era" implementations:
//
//   - Modern (2026-07-28): stateless. Every request carries its protocol
//     version and client capabilities in params._meta, mirrored into the
//     MCP-Protocol-Version, Mcp-Method and Mcp-Name headers, which the server
//     must check against the body. server/discover replaces initialize.
//   - Legacy (2025-11-25, 2025-06-18, 2025-03-26): an initialize handshake
//     opens a session named by the Mcp-Session-Id header.
//
// In both, a POST body is exactly one JSON-RPC message: batching was removed
// in 2025-06-18.
package mcp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/laiwf94/authz/internal/agents/jsonrpc"
)

// Protocol versions.
const (
	VersionModern = "2026-07-28"
	Version251125 = "2025-11-25"
	Version250618 = "2025-06-18"
	Version250326 = "2025-03-26"
)

// SupportedVersions lists every version served, newest first.
var SupportedVersions = []string{VersionModern, Version251125, Version250618, Version250326}

// LegacyVersions are the handshake-based versions.
var LegacyVersions = []string{Version251125, Version250618, Version250326}

// IsLegacy reports whether v is a supported handshake-based version.
func IsLegacy(v string) bool {
	for _, l := range LegacyVersions {
		if v == l {
			return true
		}
	}
	return false
}

// HTTP headers.
const (
	HeaderProtocolVersion = "MCP-Protocol-Version"
	HeaderSessionID       = "Mcp-Session-Id"
	HeaderMethod          = "Mcp-Method"
	HeaderName            = "Mcp-Name"
	HeaderParamPrefix     = "Mcp-Param-"
)

// _meta keys.
const (
	MetaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	MetaClientInfo         = "io.modelcontextprotocol/clientInfo"
	MetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	MetaServerInfo         = "io.modelcontextprotocol/serverInfo"
)

// Methods.
const (
	MethodInitialize  = "initialize"
	MethodInitialized = "notifications/initialized"
	MethodPing        = "ping"
	MethodDiscover    = "server/discover"
	MethodToolsList   = "tools/list"
	MethodToolsCall   = "tools/call"
)

// MCP error codes (2026-07-28 reserves -32020 to -32099 for the
// specification).
const (
	CodeHeaderMismatch             = -32020
	CodeMissingRequiredCapability  = -32021
	CodeUnsupportedProtocolVersion = -32022
)

// Application error codes used by toolgate. They sit outside the JSON-RPC
// reserved range (-32768 to -32000), as the specification asks.
const (
	CodeUnauthenticated  = -31000
	CodePolicyDenied     = -31001
	CodeRateLimited      = -31002
	CodeQuotaExceeded    = -31003
	CodeApprovalPending  = -31004
	CodeApprovalDenied   = -31005
	CodeToolQuarantined  = -31006
	CodeUpstreamError    = -31007
	CodeUpstreamTimeout  = -31008
	CodeUpstreamBusy     = -31009
	CodeAuditUnavailable = -31010
	// -31011 is kept for result rules (#87).
	CodeCheckUnavailable = -31012 // a relationship check could not be made
)

// Implementation identifies a client or server (clientInfo / serverInfo).
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Error is a JSON-RPC error with the HTTP status to send it with.
type Error struct {
	RPC        *jsonrpc.Error
	Status     int           // 0 means 200
	RetryAfter time.Duration // sets Retry-After when positive
	// Challenge is sent in WWW-Authenticate with a 401 or 403. Such an
	// error keeps its status in a legacy session too: the authorization
	// specification asks for these statuses in every revision.
	Challenge *Challenge
}

func (e *Error) Error() string { return e.RPC.Error() }

// NewError builds an *Error.
func NewError(status, code int, format string, args ...any) *Error {
	return &Error{RPC: jsonrpc.NewError(code, format, args...), Status: status}
}

// Tool is a tool definition, limited to the fields toolgate passes on.
// Icons and _meta are dropped: icon URIs are fetched by clients and are a
// tracking and SSRF surface, and neither is needed to call the tool.
type Tool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
}

var toolNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// ValidToolName reports whether name follows the specification's tool name
// rules (1 to 128 of A-Z a-z 0-9 _ - .).
func ValidToolName(name string) bool { return toolNameRe.MatchString(name) }

// Canonical returns the definition in canonical JSON (sorted keys, no
// insignificant whitespace), so that reformatting by the upstream does not
// change its hash but any change of content does.
func (t Tool) Canonical() ([]byte, error) {
	m := map[string]any{"name": t.Name}
	if t.Title != "" {
		m["title"] = t.Title
	}
	if t.Description != "" {
		m["description"] = t.Description
	}
	for k, raw := range map[string]json.RawMessage{"inputSchema": t.InputSchema, "outputSchema": t.OutputSchema, "annotations": t.Annotations} {
		if raw == nil {
			continue
		}
		v, err := jsonrpc.DecodeValue(raw)
		if err != nil {
			return nil, fmt.Errorf("tool %q: %s: %w", t.Name, k, err)
		}
		if _, ok := v.(map[string]any); !ok {
			return nil, fmt.Errorf("tool %q: %s must be an object", t.Name, k)
		}
		m[k] = v
	}
	if t.InputSchema == nil {
		return nil, fmt.Errorf("tool %q: inputSchema is required", t.Name)
	}
	return jsonrpc.Canonical(m)
}

const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

func plainHeaderSafe(s string) bool {
	if s == "" {
		return true
	}
	if s[0] == ' ' || s[0] == '\t' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 || c > 0x7e) && c != '\t' {
			return false
		}
	}
	return !(strings.HasPrefix(s, sentinelPrefix) && strings.HasSuffix(s, sentinelSuffix))
}

// EncodeHeaderValue encodes a value for Mcp-Name or Mcp-Param-*: as is when
// it is plain visible ASCII, otherwise in the =?base64?…?= form.
func EncodeHeaderValue(s string) string {
	if plainHeaderSafe(s) {
		return s
	}
	return sentinelPrefix + base64.StdEncoding.EncodeToString([]byte(s)) + sentinelSuffix
}

// DecodeHeaderValue reverses EncodeHeaderValue.
func DecodeHeaderValue(h string) (string, error) {
	if strings.HasPrefix(h, sentinelPrefix) && strings.HasSuffix(h, sentinelSuffix) && len(h) >= len(sentinelPrefix)+len(sentinelSuffix) {
		b, err := base64.StdEncoding.Strict().DecodeString(h[len(sentinelPrefix) : len(h)-len(sentinelSuffix)])
		if err != nil || !utf8.Valid(b) {
			return "", errors.New("invalid base64 header value")
		}
		return string(b), nil
	}
	for i := 0; i < len(h); i++ {
		if c := h[i]; (c < 0x20 || c > 0x7e) && c != '\t' {
			return "", errors.New("header value has invalid characters")
		}
	}
	return h, nil
}

// HeaderParam is a tool argument mirrored into an Mcp-Param-{Name} header.
type HeaderParam struct {
	Name string   // header name suffix
	Path []string // chain of property names from the arguments root
}

var tcharRe = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// instanceKeywords hold JSON instances, not schemas; an "x-mcp-header" key
// inside them is data.
var instanceKeywords = map[string]bool{"enum": true, "const": true, "default": true, "examples": true}

// HeaderParams finds the x-mcp-header annotations in an input schema and
// checks the specification's constraints: a token name, unique ignoring case,
// on an integer, string or boolean property reachable from the root through
// "properties" alone. A violation makes the whole tool definition invalid.
func HeaderParams(inputSchema json.RawMessage) ([]HeaderParam, error) {
	v, err := jsonrpc.DecodeValue(inputSchema)
	if err != nil {
		return nil, err
	}
	var out []HeaderParam
	seen := map[string]bool{}
	var walk func(node any, static bool, path []string) error
	walk = func(node any, static bool, path []string) error {
		switch n := node.(type) {
		case []any:
			for _, e := range n {
				if err := walk(e, false, nil); err != nil {
					return err
				}
			}
		case map[string]any:
			if raw, ok := n["x-mcp-header"]; ok {
				name, _ := raw.(string)
				switch {
				case !static || len(path) == 0:
					return errors.New("x-mcp-header is only allowed on properties reachable through \"properties\"")
				case !tcharRe.MatchString(name):
					return fmt.Errorf("x-mcp-header %q is not a valid header name", name)
				case seen[strings.ToLower(name)]:
					return fmt.Errorf("x-mcp-header %q is used twice", name)
				}
				if t, _ := n["type"].(string); t != "string" && t != "integer" && t != "boolean" {
					return fmt.Errorf("x-mcp-header %q must be on a string, integer or boolean property", name)
				}
				seen[strings.ToLower(name)] = true
				out = append(out, HeaderParam{Name: name, Path: append([]string(nil), path...)})
			}
			keys := make([]string, 0, len(n))
			for k := range n {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				switch {
				case k == "properties":
					props, ok := n[k].(map[string]any)
					if !ok {
						continue
					}
					names := make([]string, 0, len(props))
					for name := range props {
						names = append(names, name)
					}
					sort.Strings(names)
					for _, name := range names {
						if err := walk(props[name], static, append(path, name)); err != nil {
							return err
						}
					}
				case instanceKeywords[k] || k == "x-mcp-header":
				default:
					if err := walk(n[k], false, nil); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := walk(v, true, nil); err != nil {
		return nil, err
	}
	return out, nil
}

// paramValue returns the header text for a parameter's value in args,
// whether a value is present (absent and null both mean no header), and
// whether it is an integer.
func paramValue(p HeaderParam, args map[string]any) (text string, present, isInt bool, err error) {
	var cur any = args
	for _, k := range p.Path {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false, false, nil
		}
		if cur, ok = m[k]; !ok {
			return "", false, false, nil
		}
	}
	switch v := cur.(type) {
	case nil:
		return "", false, false, nil
	case string:
		return v, true, false, nil
	case bool:
		return strconv.FormatBool(v), true, false, nil
	case json.Number:
		f, ferr := strconv.ParseFloat(v.String(), 64)
		if ferr != nil || f != math.Trunc(f) || math.Abs(f) > 1<<53-1 {
			return "", false, false, fmt.Errorf("argument %s must be an integer in the safe range", strings.Join(p.Path, "."))
		}
		return strconv.FormatInt(int64(f), 10), true, true, nil
	default:
		return "", false, false, fmt.Errorf("argument %s must be a string, integer or boolean", strings.Join(p.Path, "."))
	}
}

// ParamHeaders computes the Mcp-Param-* headers a client must send.
func ParamHeaders(params []HeaderParam, args map[string]any) (http.Header, error) {
	h := http.Header{}
	for _, p := range params {
		v, ok, _, err := paramValue(p, args)
		if err != nil {
			return nil, err
		}
		if ok {
			h.Set(HeaderParamPrefix+p.Name, EncodeHeaderValue(v))
		}
	}
	return h, nil
}

// CheckParamHeaders verifies that the Mcp-Param-* headers of a request match
// its arguments, as a server that reads the body must.
func CheckParamHeaders(h http.Header, params []HeaderParam, args map[string]any) error {
	for _, p := range params {
		want, present, isInt, err := paramValue(p, args)
		if err != nil {
			return err
		}
		got := h.Values(HeaderParamPrefix + p.Name)
		switch {
		case !present && len(got) == 0:
			continue
		case !present:
			return fmt.Errorf("header %s%s is set but the argument is absent", HeaderParamPrefix, p.Name)
		case len(got) != 1:
			return fmt.Errorf("header %s%s must be sent exactly once", HeaderParamPrefix, p.Name)
		}
		dec, err := DecodeHeaderValue(got[0])
		if err != nil {
			return fmt.Errorf("header %s%s: %v", HeaderParamPrefix, p.Name, err)
		}
		if dec == want {
			continue
		}
		// Integers compare numerically, so a header of "42.0" matches 42.
		if f, err := strconv.ParseFloat(dec, 64); isInt && err == nil && strconv.FormatFloat(f, 'f', -1, 64) == want {
			continue
		}
		return fmt.Errorf("header %s%s does not match the argument value", HeaderParamPrefix, p.Name)
	}
	return nil
}
