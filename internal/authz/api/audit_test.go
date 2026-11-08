package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/logging"
	"github.com/laiwf94/authz/internal/platform/logging/logtest"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

const secondKey = "second-key-0123456789"

type auditHarness struct {
	t    *testing.T
	srv  *httptest.Server
	log  *audit.Log
	path string
	m    *metrics.Registry
	logs *lockedBuffer
	tok  *token.Issuer
}

func newAuditHarness(t *testing.T) *auditHarness {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := audit.OpenWith(path, audit.Options{Schemas: audit.Default()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{7}, token.KeySize))
	h := &auditHarness{t: t, log: l, path: path, m: metrics.New(), logs: &lockedBuffer{}, tok: tok}
	s, err := New(Config{Store: st, Tokens: tok, APIKeys: []string{apiKey, secondKey}, Metrics: h.m,
		Logger: logging.NewLogger(h.logs, logging.Options{}), Audit: l})
	if err != nil {
		t.Fatal(err)
	}
	h.srv = httptest.NewServer(s)
	t.Cleanup(h.srv.Close)
	return h
}

// do sends one request. rid, when set, is sent as the traceparent when it
// is one ("00-…") and as the X-Request-Id otherwise.
func (h *auditHarness) do(method, path, key, rid string, body any) (int, map[string]any) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if strings.HasPrefix(rid, "00-") {
		req.Header.Set("Traceparent", rid)
	} else if rid != "" {
		req.Header.Set("X-Request-Id", rid)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (h *auditHarness) records() []audit.Record {
	h.t.Helper()
	raw, err := os.ReadFile(h.path)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := audit.VerifyWith(bytes.NewReader(raw), audit.Default()); err != nil {
		h.t.Fatalf("audit log does not verify: %v\n%s", err, raw)
	}
	var out []audit.Record
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r audit.Record
		if err := json.Unmarshal(line, &r); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// traceSchema is the traceparent the schema write is sent with.
const traceSchema = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

// logged reports whether a request line with request ID rid carries
// correlation ID corr, a trace ID.
func (h *auditHarness) logged(rid, corr string) bool {
	if logging.Traceparent(corr) == "" {
		return false
	}
	for _, l := range strings.Split(h.logs.String(), "\n") {
		var m struct {
			Msg           string `json:"msg"`
			RequestID     string `json:"request_id"`
			CorrelationID string `json:"correlation_id"`
		}
		if json.Unmarshal([]byte(l), &m) == nil && m.Msg == "request" && m.RequestID == rid && m.CorrelationID == corr {
			return true
		}
	}
	return false
}

func TestKeyID(t *testing.T) {
	a, b := KeyID(apiKey), KeyID(secondKey)
	if a == b || !strings.HasPrefix(a, "api_key:") || len(a) != len("api_key:")+8 || KeyID(apiKey) != a {
		t.Fatalf("KeyID: %q %q", a, b)
	}
	// It is not a prefix of the key's plain SHA-256, which the server keeps
	// and an attacker with a guess could compare.
	sum := sha256.Sum256([]byte(apiKey))
	if strings.HasPrefix(hex.EncodeToString(sum[:]), a[len("api_key:"):]) {
		t.Fatal("KeyID is the key's plain hash")
	}
}

// TestAuditSchemaAndWrites: schema changes and relationship writes are
// typed records in a chain that verifies, with the key's ID as the actor and
// the request's correlation ID (its traceparent's trace ID, or the generated
// one on its log line); reads, checks and refused requests write nothing.
func TestAuditSchemaAndWrites(t *testing.T) {
	h := newAuditHarness(t)
	scan := logtest.Check(t).Known(apiKey, secondKey)
	scan.File(h.path)
	defer func() { scan.Bytes("serve log", []byte(h.logs.String())) }()
	code, out := h.do("PUT", "/v1/schema", apiKey, traceSchema, map[string]string{"schema": schemaSrc})
	if code != 200 {
		t.Fatalf("schema: %d %v", code, out)
	}
	schemaAt := out["written_at"].(string)
	code, out = h.do("POST", "/v1/relationships/write", secondKey, "", map[string]any{
		"updates": []map[string]string{
			{"op": "touch", "relationship": "doc:readme#owner@user:alice"},
			{"op": "create", "relationship": "doc:readme#viewer@user:bob"},
			{"op": "touch", "relationship": "doc:plan#viewer@group:eng#member"},
		},
	})
	if code != 200 {
		t.Fatalf("write: %d %v", code, out)
	}
	writeAt := out["written_at"].(string)
	code, out = h.do("POST", "/v1/relationships/write", apiKey, "req-delete", map[string]any{
		"updates":       []map[string]string{{"op": "delete", "relationship": "doc:readme#viewer@user:bob"}},
		"preconditions": []map[string]any{{"must_exist": true, "filter": map[string]string{"resource_type": "doc", "resource_id": "readme"}}},
	})
	if code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}

	// None of these write a record.
	h.do("POST", "/v1/check", apiKey, "", map[string]string{"resource": "doc:readme", "permission": "view", "subject": "user:alice"})
	h.do("POST", "/v1/relationships/read", apiKey, "", map[string]any{"filter": map[string]string{"resource_type": "doc"}})
	h.do("GET", "/v1/schema", apiKey, "", nil)
	if code, _ := h.do("PUT", "/v1/schema", "wrong-key-0123456789", "", map[string]string{"schema": schemaSrc}); code != 401 {
		t.Fatal("unauthenticated schema write")
	}
	if code, _ := h.do("PUT", "/v1/schema", apiKey, "", map[string]string{"schema": "definition {"}); code != 400 {
		t.Fatal("invalid schema")
	}
	if code, _ := h.do("POST", "/v1/relationships/write", apiKey, "", map[string]any{
		"updates": []map[string]string{{"op": "create", "relationship": "doc:readme#owner@user:alice"}}}); code != 409 {
		t.Fatal("conflicting create")
	}

	recs := h.records()
	if len(recs) != 3 {
		t.Fatalf("%d records, want 3: %+v", len(recs), recs)
	}
	sr := recs[0]
	var sp audit.SchemaWritten
	json.Unmarshal(sr.Data, &sp)
	sum := sha256.Sum256([]byte(schemaText(t, h)))
	if sr.Event != audit.EventSchemaWritten || sr.Actor != KeyID(apiKey) || sr.Action != "schema.write" ||
		sr.CorrelationID != "0af7651916cd43dd8448eb211c80319c" || sp.Revision != schemaAt || sp.SHA256 != hex.EncodeToString(sum[:]) || sp.Bytes == 0 {
		t.Errorf("schema record: %+v %+v", sr.Envelope, sp)
	}
	wr := recs[1]
	var wp audit.RelationshipsWritten
	json.Unmarshal(wr.Data, &wp)
	if wr.Event != audit.EventRelationshipsWritten || wr.Actor != KeyID(secondKey) || wr.Action != "relationships.write" ||
		logging.Traceparent(wr.CorrelationID) == "" || wp != (audit.RelationshipsWritten{Revision: writeAt, Touch: 2, Create: 1}) {
		t.Errorf("write record: %+v %+v", wr.Envelope, wp)
	}
	var dp audit.RelationshipsWritten
	json.Unmarshal(recs[2].Data, &dp)
	if !h.logged("req-delete", recs[2].CorrelationID) || dp.Delete != 1 || dp.Preconditions != 1 || dp.Touch+dp.Create != 0 {
		t.Errorf("delete record: %+v %+v", recs[2].Envelope, dp)
	}

	// No key and no schema text is in the log.
	raw, _ := os.ReadFile(h.path)
	for _, s := range []string{apiKey, secondKey, "permission view"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("audit log contains %q", s)
		}
	}
	var mb strings.Builder
	h.m.Write(&mb)
	for _, want := range []string{`grantd_audit_records_total{event="authz.schema_written"} 1`,
		`grantd_audit_records_total{event="authz.relationships_written"} 2`} {
		if !strings.Contains(mb.String(), want) {
			t.Errorf("metrics lack %s:\n%s", want, mb.String())
		}
	}
}

func schemaText(t *testing.T, h *auditHarness) string {
	t.Helper()
	code, out := h.do("GET", "/v1/schema", apiKey, "", nil)
	if code != 200 {
		t.Fatal(code)
	}
	return out["schema"].(string)
}

// TestAuditWriteFailure: a write that commits while the audit log is broken
// still succeeds; the failure is counted and logged and /healthz answers 503.
func TestAuditWriteFailure(t *testing.T) {
	h := newAuditHarness(t)
	if code, _ := h.do("GET", "/healthz", "", "", nil); code != 200 {
		t.Fatal("healthy at start")
	}
	h.log.Close()
	if code, out := h.do("PUT", "/v1/schema", apiKey, "", map[string]string{"schema": schemaSrc}); code != 200 {
		t.Fatalf("schema write with a broken audit log: %d %v", code, out)
	}
	if !strings.Contains(h.logs.String(), `"msg":"audit write failed"`) {
		t.Fatalf("no failure logged:\n%s", h.logs.String())
	}
	var mb strings.Builder
	h.m.Write(&mb)
	if !strings.Contains(mb.String(), "grantd_audit_failures_total 1") {
		t.Errorf("metrics:\n%s", mb.String())
	}
	code, out := h.do("GET", "/healthz", "", "", nil)
	if code != 503 || out["status"] != "audit log unavailable" || out["revision"] == nil {
		t.Fatalf("healthz: %d %v", code, out)
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }
