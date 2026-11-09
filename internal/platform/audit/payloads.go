package audit

import "sync"

// The payload schemas of the three tracks. Each event type is a struct: its
// json names are the payload's fields, and a field without omitempty is
// required (present and, for a string, not empty). Default registers them
// all. Event types of the authz and authn tracks are prefixed with the
// track; the agents track keeps toolgate's unprefixed names, so the logs
// toolgate wrote verify against these schemas unchanged.
//
// Envelope conventions: Actor is who caused the event, Subject what it acted
// on, Action the operation (see each type), Decision allow or deny.

// --- authz track (grantd, authz serve) ---

// SchemaWritten is a schema change. Envelope: actor (the API key or
// service), action "schema.write".
type SchemaWritten struct {
	Revision string `json:"revision"` // the zed token of the write
	SHA256   string `json:"sha256"`   // of the schema source
	Bytes    int    `json:"bytes"`
}

// RelationshipsWritten is one write request. Envelope: actor, action
// "relationships.write".
type RelationshipsWritten struct {
	Revision      string `json:"revision"`
	Touch         int    `json:"touch"`
	Create        int    `json:"create"`
	Delete        int    `json:"delete"`
	Preconditions int    `json:"preconditions"`
}

// CheckDecided is a decision record for one permission check. Envelope:
// subject (the resource, "document:readme"), action (the permission),
// decision.
type CheckDecided struct {
	Principal string `json:"principal"` // who was checked, "user:alice"
	Revision  string `json:"revision"`  // the zed token it was checked at
	Bulk      int    `json:"bulk,omitempty"`
}

// --- authn track (wicket, authz gateway) ---

// LoginSucceeded is a completed sign-in. Envelope: actor (the user's
// subject), action "login", decision allow.
type LoginSucceeded struct {
	Provider string `json:"provider"`
	App      string `json:"app,omitempty"`
	Session  string `json:"session"` // the session ID, not the cookie
	Email    string `json:"email,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
}

// LoginFailed is a sign-in the identity provider or the response broke.
// Envelope: action "login", decision deny.
type LoginFailed struct {
	Reason   string `json:"reason"`
	Provider string `json:"provider,omitempty"`
	App      string `json:"app,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
	Error    string `json:"error,omitempty"`
}

// LoginRejected is a sign-in refused before it reached a provider.
// Envelope: action "login", decision deny.
type LoginRejected struct {
	Reason string `json:"reason"`
	App    string `json:"app,omitempty"`
}

// Logout is a session ended by its user. Envelope: actor, action "logout".
type Logout struct {
	Provider string `json:"provider,omitempty"`
	Session  string `json:"session"`
}

// LogoutRejected is a logout that failed its CSRF check. Envelope: action
// "logout", decision deny.
type LogoutRejected struct {
	Reason  string `json:"reason"`
	Session string `json:"session,omitempty"`
}

// SessionRevoked is an administrator ending sessions. Envelope: actor (the
// administrator), subject (the session or user), action "session.revoke".
type SessionRevoked struct {
	Session  string `json:"session,omitempty"`
	Provider string `json:"provider,omitempty"`
	Count    int    `json:"count,omitempty"`
	By       string `json:"by"`
}

// AccessDenied is a forward-auth request refused by an application's
// policy. Envelope: subject (the application), action "access", decision
// deny.
type AccessDenied struct {
	Reason   string `json:"reason"`
	App      string `json:"app,omitempty"`
	Host     string `json:"host,omitempty"`
	Provider string `json:"provider,omitempty"`
	Session  string `json:"session,omitempty"`
}

// ConfigLoaded is a configuration (re)load. Envelope: action "config.load".
type ConfigLoaded struct {
	Providers int `json:"providers"`
	Apps      int `json:"apps"`
}

// ConfigLoadFailed is a rejected configuration. Envelope: action
// "config.load".
type ConfigLoadFailed struct {
	Error string `json:"error"`
}

// --- agents track (toolgate, authz mcp) ---

// ToolCall is one stage of a tool call: refused, started or completed.
type ToolCall struct {
	Agent            string `json:"agent"`
	Owner            string `json:"owner,omitempty"`
	Auth             string `json:"auth"`
	KeyID            string `json:"key_id,omitempty"`
	RequestedTool    string `json:"requested_tool,omitempty"` // a refused name, cut short
	Upstream         string `json:"upstream,omitempty"`
	Tool             string `json:"tool,omitempty"`
	ArgsHMAC         string `json:"args_hmac,omitempty"`
	ArgsPreview      string `json:"args_preview,omitempty"`
	Policy           string `json:"policy,omitempty"`
	Protocol         string `json:"protocol,omitempty"`
	RuleID           string `json:"rule_id,omitempty"`
	ConstraintRuleID string `json:"constraint_rule_id,omitempty"`
	Reason           string `json:"reason,omitempty"`
	ApprovalID       string `json:"approval_id,omitempty"`
	Decision         string `json:"decision"`
	Stage            string `json:"stage"`
	Outcome          string `json:"outcome,omitempty"`
	LatencyMS        int64  `json:"latency_ms,omitempty"`
	ResponseBytes    int    `json:"response_bytes,omitempty"`
	Redactions       int    `json:"redactions,omitempty"`
	Truncated        bool   `json:"truncated,omitempty"`
	UpstreamCode     int    `json:"upstream_code,omitempty"`
	Error            string `json:"error,omitempty"`
	RequestID        string `json:"request_id,omitempty"`
}

// ApprovalRequested is a call held for a human.
type ApprovalRequested struct {
	ApprovalID  string `json:"approval_id"`
	Agent       string `json:"agent"`
	Tool        string `json:"tool"`
	RuleID      string `json:"rule_id,omitempty"`
	ArgsHMAC    string `json:"args_hmac,omitempty"`
	ArgsPreview string `json:"args_preview,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
}

// ApprovalDecided is a human's answer to an approval request.
type ApprovalDecided struct {
	ApprovalID string `json:"approval_id"`
	Decision   string `json:"decision"` // approved or denied
	Agent      string `json:"agent"`
	Tool       string `json:"tool"`
	ArgsSHA256 string `json:"args_sha256"`
	Note       string `json:"note,omitempty"`
	ExpiresAt  string `json:"expires_at"`
	RequestID  string `json:"request_id,omitempty"`
}

// ToolApproved is an administrator trusting a changed tool definition.
type ToolApproved struct {
	Tool      string `json:"tool"`
	Hash      string `json:"hash"`
	RequestID string `json:"request_id,omitempty"`
}

// ToolQuarantined is a tool whose definition changed.
type ToolQuarantined struct {
	Tool        string `json:"tool"`
	TrustedHash string `json:"trusted_hash"`
	NewHash     string `json:"new_hash"`
	RequestID   string `json:"request_id,omitempty"`
}

// PolicyApplied is a policy (re)load that took effect.
type PolicyApplied struct {
	Previous  string `json:"previous,omitempty"`
	Current   string `json:"current"`
	RequestID string `json:"request_id,omitempty"`
}

// PolicyRejected is a policy reload that failed; the previous one stays.
type PolicyRejected struct {
	Previous  string `json:"previous,omitempty"`
	Current   string `json:"current,omitempty"`
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

// Event types.
const (
	EventSchemaWritten        = "authz.schema_written"
	EventRelationshipsWritten = "authz.relationships_written"
	EventCheckDecided         = "authz.check_decided"

	EventLoginSucceeded   = "authn.login_succeeded"
	EventLoginFailed      = "authn.login_failed"
	EventLoginRejected    = "authn.login_rejected"
	EventLogout           = "authn.logout"
	EventLogoutRejected   = "authn.logout_rejected"
	EventSessionRevoked   = "authn.session_revoked"
	EventAccessDenied     = "authn.access_denied"
	EventConfigLoaded     = "authn.config_loaded"
	EventConfigLoadFailed = "authn.config_load_failed"

	EventToolCall          = "tool_call"
	EventApprovalRequested = "approval_requested"
	EventApprovalDecided   = "approval_decided"
	EventToolApproved      = "tool_approved"
	EventToolQuarantined   = "tool_quarantined"
	EventPolicyApplied     = "policy_applied"
	EventPolicyRejected    = "policy_rejected"
)

func (SchemaWritten) AuditEvent() string        { return EventSchemaWritten }
func (RelationshipsWritten) AuditEvent() string { return EventRelationshipsWritten }
func (CheckDecided) AuditEvent() string         { return EventCheckDecided }
func (LoginSucceeded) AuditEvent() string       { return EventLoginSucceeded }
func (LoginFailed) AuditEvent() string          { return EventLoginFailed }
func (LoginRejected) AuditEvent() string        { return EventLoginRejected }
func (Logout) AuditEvent() string               { return EventLogout }
func (LogoutRejected) AuditEvent() string       { return EventLogoutRejected }
func (SessionRevoked) AuditEvent() string       { return EventSessionRevoked }
func (AccessDenied) AuditEvent() string         { return EventAccessDenied }
func (ConfigLoaded) AuditEvent() string         { return EventConfigLoaded }
func (ConfigLoadFailed) AuditEvent() string     { return EventConfigLoadFailed }
func (ToolCall) AuditEvent() string             { return EventToolCall }
func (ApprovalRequested) AuditEvent() string    { return EventApprovalRequested }
func (ApprovalDecided) AuditEvent() string      { return EventApprovalDecided }
func (ToolApproved) AuditEvent() string         { return EventToolApproved }
func (ToolQuarantined) AuditEvent() string      { return EventToolQuarantined }
func (PolicyApplied) AuditEvent() string        { return EventPolicyApplied }
func (PolicyRejected) AuditEvent() string       { return EventPolicyRejected }

// Defs are the definitions Default registers, in track order.
func Defs() []Def {
	return []Def{
		{TrackAuthz, SchemaWritten{}, NeedActor | NeedAction},
		{TrackAuthz, RelationshipsWritten{}, NeedActor | NeedAction},
		{TrackAuthz, CheckDecided{}, NeedSubject | NeedAction | NeedDecision},

		{TrackAuthn, LoginSucceeded{}, NeedActor | NeedAction | NeedDecision},
		{TrackAuthn, LoginFailed{}, NeedAction | NeedDecision},
		{TrackAuthn, LoginRejected{}, NeedAction | NeedDecision},
		{TrackAuthn, Logout{}, NeedActor | NeedAction},
		{TrackAuthn, LogoutRejected{}, NeedAction | NeedDecision},
		{TrackAuthn, SessionRevoked{}, NeedActor | NeedSubject | NeedAction},
		{TrackAuthn, AccessDenied{}, NeedSubject | NeedAction | NeedDecision},
		{TrackAuthn, ConfigLoaded{}, NeedAction},
		{TrackAuthn, ConfigLoadFailed{}, NeedAction},

		// toolgate's records carry no envelope.
		{TrackAgents, ToolCall{}, 0},
		{TrackAgents, ApprovalRequested{}, 0},
		{TrackAgents, ApprovalDecided{}, 0},
		{TrackAgents, ToolApproved{}, 0},
		{TrackAgents, ToolQuarantined{}, 0},
		{TrackAgents, PolicyApplied{}, 0},
		{TrackAgents, PolicyRejected{}, 0},

		// The log's own records (rotate.go).
		{TrackAudit, SegmentStarted{}, NeedAction},
	}
}

var defaultSchemas = sync.OnceValue(func() *Schemas {
	s, err := NewSchemas(Defs()...)
	if err != nil {
		panic(err)
	}
	return s
})

// Default returns the platform's event types: every track's payloads.
func Default() *Schemas { return defaultSchemas() }
