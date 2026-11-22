// Package products sets up the products the benchmark compares with authz
// and talks to their authorization APIs: SpiceDB's HTTP gateway and
// OpenFGA's HTTP API take the same seeded dataset (bench/datasets) as
// authz does, and answer the same checks. compose.yaml in this directory
// runs each product at a pinned version with its recommended production
// settings; README.md says what each setting is and why.
//
// Every product is reached through a Target: Setup writes the dataset's
// schema or model, Writes is the loader's format for its write API, and
// Check asks one question. CrossCheck asks every target the same sampled
// checks and fails on the first disagreement, which proves the setups
// before any number is measured on them.
package products

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/laiwf94/authz/bench/datasets"
)

// OpenFGAModel is datasets.OpenFGAModel as the JSON authorization model
// OpenFGA's API takes, as `fga model transform` (openfga/cli, the version
// pinned in compose.yaml) writes it; verify.sh regenerates it and fails on
// any difference.
//
//go:embed openfga-model.json
var OpenFGAModel []byte

// Target is one product's authorization API.
type Target interface {
	// Name is the product: authz, spicedb or openfga.
	Name() string
	// Setup writes the dataset's schema or model, so that the product
	// takes the dataset's relationships and answers its checks.
	Setup(ctx context.Context) error
	// Loader writes relationships to the product.
	Loader() *datasets.Loader
	// Check asks whether subject (type:id or type:id#relation) has
	// permission on resource (type:id). Fresh asks for the newest data
	// instead of the product's fastest read.
	Check(ctx context.Context, resource, permission, subject string, fresh bool) (bool, error)
}

// conn is what every target shares: the HTTP client, base URL and key.
type conn struct {
	Client *http.Client
	URL    string // base URL, such as http://127.0.0.1:8443
	Key    string // API key or preshared key, sent as a bearer token
}

func (c *conn) loader(format *datasets.WriteFormat) *datasets.Loader {
	return &datasets.Loader{Client: c.Client, URL: c.URL, Key: c.Key, Format: format}
}

// post sends body as JSON and decodes a 200 answer into out. A check is
// not retried: a failed one is a failed sample.
func (c *conn) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.URL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Key)
	hc := c.Client
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, bytes.TrimSpace(answer[:min(len(answer), 512)]))
	}
	if err := json.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	return nil
}

// object splits type:id (or type:id#relation) into its parts.
func object(s string) (typ, id, rel string, err error) {
	typ, rest, ok := strings.Cut(s, ":")
	if !ok || typ == "" || rest == "" {
		return "", "", "", fmt.Errorf("object %q: want type:id", s)
	}
	id, rel, _ = strings.Cut(rest, "#")
	if id == "" {
		return "", "", "", fmt.Errorf("object %q: want type:id", s)
	}
	return typ, id, rel, nil
}

// Authz is authz's own API, as `authz serve` answers it.
type Authz struct{ conn }

// NewAuthz returns the target for authz serve at url.
func NewAuthz(c *http.Client, url, key string) *Authz { return &Authz{conn{c, url, key}} }

// Name implements Target.
func (*Authz) Name() string { return "authz" }

// Setup implements Target: PUT /v1/schema.
func (a *Authz) Setup(ctx context.Context) error { return a.Loader().PutSchema(ctx, datasets.Schema) }

// Loader implements Target.
func (a *Authz) Loader() *datasets.Loader { return a.loader(nil) }

// Check implements Target: POST /v1/check.
func (a *Authz) Check(ctx context.Context, resource, permission, subject string, fresh bool) (bool, error) {
	mode := "minimize_latency"
	if fresh {
		mode = "fully_consistent"
	}
	var out struct {
		Allowed *bool `json:"allowed"`
	}
	body := map[string]any{"resource": resource, "permission": permission, "subject": subject,
		"consistency": map[string]string{"mode": mode}}
	if err := a.post(ctx, "/v1/check", body, &out); err != nil {
		return false, err
	}
	if out.Allowed == nil {
		return false, errors.New("authz check answer has no allowed field")
	}
	return *out.Allowed, nil
}

// SpiceDB is SpiceDB's HTTP gateway (spicedb serve --http-enabled), which
// takes the dataset's schema as it is.
type SpiceDB struct{ conn }

// NewSpiceDB returns the target for SpiceDB's HTTP gateway at url, with
// one of its --grpc-preshared-key values.
func NewSpiceDB(c *http.Client, url, key string) *SpiceDB { return &SpiceDB{conn{c, url, key}} }

// Name implements Target.
func (*SpiceDB) Name() string { return "spicedb" }

// Setup implements Target: POST /v1/schema/write.
func (s *SpiceDB) Setup(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{"schema": datasets.Schema})
	_, err := s.Loader().Call(ctx, http.MethodPost, "/v1/schema/write", body)
	return err
}

// SpiceDBMaxBatch is SpiceDB's default
// --write-relationships-max-updates-per-call.
const SpiceDBMaxBatch = 1000

// SpiceDBWrites is POST /v1/relationships/write of OPERATION_TOUCH updates.
var SpiceDBWrites = datasets.WriteFormat{
	Path:     "/v1/relationships/write",
	MaxBatch: SpiceDBMaxBatch,
	Begin:    func(b []byte) []byte { return append(b, `{"updates":[`...) },
	Append: func(b []byte, r *datasets.Relationship) []byte {
		b = append(b, `{"operation":"OPERATION_TOUCH","relationship":{"resource":`...)
		b = appendSpiceDBObject(b, r.ResourceType, r.Resource)
		b = append(b, `,"relation":"`...)
		b = append(b, r.Relation...)
		b = append(b, `","subject":{"object":`...)
		b = appendSpiceDBObject(b, r.SubjectType, r.Subject)
		if r.SubjectRelation != "" {
			b = append(b, `,"optionalRelation":"`...)
			b = append(b, r.SubjectRelation...)
			b = append(b, '"')
		}
		return append(b, "}}}"...)
	},
	End: func(b []byte) []byte { return append(b, "]}"...) },
}

// appendSpiceDBObject appends {"objectType":...,"objectId":...}; the
// wildcard's ID is "*".
func appendSpiceDBObject(b []byte, typ string, n int) []byte {
	b = append(b, `{"objectType":"`...)
	b = append(b, typ...)
	b = append(b, `","objectId":"`...)
	if n == datasets.Wildcard {
		b = append(b, '*')
	} else {
		b = append(b, typ[0])
		b = strconv.AppendInt(b, int64(n), 10)
	}
	return append(b, `"}`...)
}

// Loader implements Target.
func (s *SpiceDB) Loader() *datasets.Loader { return s.loader(&SpiceDBWrites) }

type spiceObject struct {
	Type string `json:"objectType"`
	ID   string `json:"objectId"`
}

// Check implements Target: POST /v1/permissions/check.
func (s *SpiceDB) Check(ctx context.Context, resource, permission, subject string, fresh bool) (bool, error) {
	rt, rid, rrel, err := object(resource)
	if err != nil {
		return false, err
	}
	if rrel != "" {
		return false, fmt.Errorf("resource %q has a relation", resource)
	}
	st, sid, srel, err := object(subject)
	if err != nil {
		return false, err
	}
	consistency := map[string]bool{"minimizeLatency": true}
	if fresh {
		consistency = map[string]bool{"fullyConsistent": true}
	}
	subj := map[string]any{"object": spiceObject{st, sid}}
	if srel != "" {
		subj["optionalRelation"] = srel
	}
	body := map[string]any{"consistency": consistency, "resource": spiceObject{rt, rid},
		"permission": permission, "subject": subj}
	var out struct {
		Permissionship string `json:"permissionship"`
	}
	if err := s.post(ctx, "/v1/permissions/check", body, &out); err != nil {
		return false, err
	}
	switch out.Permissionship {
	case "PERMISSIONSHIP_HAS_PERMISSION":
		return true, nil
	case "PERMISSIONSHIP_NO_PERMISSION":
		return false, nil
	}
	return false, fmt.Errorf("spicedb check answered permissionship %q", out.Permissionship)
}

// OpenFGA is OpenFGA's HTTP API with preshared-key authentication. Its
// data lives in a store, found or created by name in Setup, and checks
// name the authorization model Setup wrote.
type OpenFGA struct {
	conn
	StoreName string
	Store     string // store ID, set by Setup or by the caller
	Model     string // authorization model ID, set by Setup or by the caller
}

// NewOpenFGA returns the target for OpenFGA's HTTP API at url, with one of
// its --authn-preshared-keys and the store named store.
func NewOpenFGA(c *http.Client, url, key, store string) *OpenFGA {
	return &OpenFGA{conn: conn{c, url, key}, StoreName: store}
}

// Name implements Target.
func (*OpenFGA) Name() string { return "openfga" }

// OpenFGAMaxBatch is OpenFGA's default --max-tuples-per-write.
const OpenFGAMaxBatch = 100

// Setup implements Target. It finds the store named StoreName (GET
// /stores?name=), creating it if there is none, and makes the dataset's
// model current: when the store's newest model is not OpenFGAModel it
// writes it. Running it again changes nothing.
func (o *OpenFGA) Setup(ctx context.Context) error {
	l := o.loader(nil)
	answer, err := l.Call(ctx, http.MethodGet, "/stores?name="+url.QueryEscape(o.StoreName), nil)
	if err != nil {
		return err
	}
	var stores struct {
		Stores []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"stores"`
	}
	if err := json.Unmarshal(answer, &stores); err != nil {
		return fmt.Errorf("openfga stores: %w", err)
	}
	o.Store = ""
	for _, s := range stores.Stores {
		if s.Name == o.StoreName {
			o.Store = s.ID
			break
		}
	}
	if o.Store == "" {
		body, _ := json.Marshal(map[string]string{"name": o.StoreName})
		if answer, err = l.Call(ctx, http.MethodPost, "/stores", body); err != nil {
			return err
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(answer, &created); err != nil || created.ID == "" {
			return fmt.Errorf("openfga create store: no id in %q", answer)
		}
		o.Store = created.ID
	}
	answer, err = l.Call(ctx, http.MethodGet, "/stores/"+o.Store+"/authorization-models?page_size=1", nil)
	if err != nil {
		return err
	}
	var models struct {
		Models []json.RawMessage `json:"authorization_models"`
	}
	if err := json.Unmarshal(answer, &models); err != nil {
		return fmt.Errorf("openfga models: %w", err)
	}
	if len(models.Models) > 0 {
		if id, same := sameModel(models.Models[0]); same {
			o.Model = id
			return nil
		}
	}
	if answer, err = l.Call(ctx, http.MethodPost, "/stores/"+o.Store+"/authorization-models", OpenFGAModel); err != nil {
		return err
	}
	var written struct {
		ID string `json:"authorization_model_id"`
	}
	if err := json.Unmarshal(answer, &written); err != nil || written.ID == "" {
		return fmt.Errorf("openfga write model: no authorization_model_id in %q", answer)
	}
	o.Model = written.ID
	return nil
}

// sameModel reports whether a model read back from OpenFGA is
// OpenFGAModel, and its ID.
func sameModel(raw json.RawMessage) (string, bool) {
	var got, want struct {
		ID      string          `json:"id"`
		Version string          `json:"schema_version"`
		Types   json.RawMessage `json:"type_definitions"`
	}
	if json.Unmarshal(raw, &got) != nil || json.Unmarshal(OpenFGAModel, &want) != nil {
		return "", false
	}
	return got.ID, got.Version == want.Version && canonical(got.Types) == canonical(want.Types)
}

// canonical re-encodes JSON with sorted keys and no spaces.
func canonical(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// Writes is POST /stores/{store}/write of tuple keys against Model, with
// on_duplicate ignore so that a write is idempotent like a touch. Setup
// must have run.
func (o *OpenFGA) Writes() *datasets.WriteFormat {
	head := `{"authorization_model_id":"` + o.Model + `","writes":{"on_duplicate":"ignore","tuple_keys":[`
	return &datasets.WriteFormat{
		Path:     "/stores/" + o.Store + "/write",
		MaxBatch: OpenFGAMaxBatch,
		Begin:    func(b []byte) []byte { return append(b, head...) },
		Append:   datasets.AppendOpenFGA,
		End:      func(b []byte) []byte { return append(b, "]}}"...) },
	}
}

// Loader implements Target. Setup must have run.
func (o *OpenFGA) Loader() *datasets.Loader { return o.loader(o.Writes()) }

// Check implements Target: POST /stores/{store}/check.
func (o *OpenFGA) Check(ctx context.Context, resource, permission, subject string, fresh bool) (bool, error) {
	if o.Store == "" || o.Model == "" {
		return false, errors.New("openfga check before setup: no store or model")
	}
	consistency := "MINIMIZE_LATENCY"
	if fresh {
		consistency = "HIGHER_CONSISTENCY"
	}
	body := map[string]any{"authorization_model_id": o.Model, "consistency": consistency,
		"tuple_key": map[string]string{"user": subject, "relation": permission, "object": resource}}
	var out struct {
		Allowed *bool `json:"allowed"`
	}
	if err := o.post(ctx, "/stores/"+o.Store+"/check", body, &out); err != nil {
		return false, err
	}
	if out.Allowed == nil {
		return false, errors.New("openfga check answer has no allowed field")
	}
	return *out.Allowed, nil
}
