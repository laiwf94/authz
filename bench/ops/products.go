package ops

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
)

// The products an API can speak for. Each operation asks every product the
// same question in its own request and checks the answer as strictly as
// authz's: a SpiceDB permissionship other than has or has not, an OpenFGA
// batch item missing or in error, a lookup answer over its limit all fail.
const (
	ProductAuthz   = "authz"   // authz serve: /v1/check, /v1/check/bulk, /v1/lookup/resources, /v1/relationships/write
	ProductSpiceDB = "spicedb" // SpiceDB's HTTP gateway: /v1/permissions/check, /checkbulk, /resources, /v1/relationships/write
	ProductOpenFGA = "openfga" // OpenFGA's HTTP API: /stores/{id}/check, /batch-check, /list-objects, /write
)

// OpenFGAMaxBatchCheck is OpenFGA's default --max-checks-per-batch-check:
// a bulk check of more items is refused.
const OpenFGAMaxBatchCheck = 50

// Validate reports an API its operations cannot be sent to: an unknown
// product, an OpenFGA API without its store and model, or a consistency
// mode the product has no equivalent for.
func (a *API) Validate() error {
	switch a.Product {
	case "", ProductAuthz:
		return nil
	case ProductSpiceDB:
	case ProductOpenFGA:
		if a.Store == "" || a.Model == "" {
			return errors.New("openfga: the store and authorization model IDs are required")
		}
	default:
		return fmt.Errorf("product %q, want %s, %s or %s", a.Product, ProductAuthz, ProductSpiceDB, ProductOpenFGA)
	}
	switch a.Consistency {
	case "", "minimize_latency", "fully_consistent":
		return nil
	}
	return fmt.Errorf("%s: consistency %q has no equivalent; use minimize_latency or fully_consistent", a.Product, a.Consistency)
}

// fresh reports whether reads ask for the newest data.
func (a *API) fresh() bool { return a.Consistency == "fully_consistent" }

// spiceConsistency is SpiceDB's Consistency message for the mode.
func (a *API) spiceConsistency() map[string]bool {
	if a.fresh() {
		return map[string]bool{"fullyConsistent": true}
	}
	return map[string]bool{"minimizeLatency": true}
}

// fgaConsistency is OpenFGA's ConsistencyPreference for the mode.
func (a *API) fgaConsistency() string {
	if a.fresh() {
		return "HIGHER_CONSISTENCY"
	}
	return "MINIMIZE_LATENCY"
}

func (a *API) fgaPath(op string) string { return a.URL + "/stores/" + a.Store + "/" + op }

type spiceObject struct {
	Type string `json:"objectType"`
	ID   string `json:"objectId"`
}

type spiceSubject struct {
	Object spiceObject `json:"object"`
}

type spiceItem struct {
	Resource   spiceObject  `json:"resource"`
	Permission string       `json:"permission"`
	Subject    spiceSubject `json:"subject"`
}

func (k Keyspace) spiceItem(rng *rand.Rand, permission string) spiceItem {
	return spiceItem{spiceObject{k.ResourceType, k.resourceID(rng)}, permission,
		spiceSubject{spiceObject{k.SubjectType, k.subjectID(rng)}}}
}

// spiceError is a google.rpc.Status, as the gateway writes an error.
type spiceError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// spicePermissionship checks a CheckPermission answer: the dataset has no
// caveats, so a conditional or unspecified answer is wrong.
func spicePermissionship(p string) error {
	switch p {
	case "PERMISSIONSHIP_HAS_PERMISSION", "PERMISSIONSHIP_NO_PERMISSION":
		return nil
	case "":
		return errors.New("spicedb answer has no permissionship")
	}
	return fmt.Errorf("spicedb answered permissionship %s", p)
}

// spiceDB is POST /v1/permissions/check.
func (c *Check) spiceDB(ctx context.Context, rng *rand.Rand) error {
	it := c.Keys.spiceItem(rng, c.Permission)
	body := map[string]any{"consistency": c.API.spiceConsistency(), "resource": it.Resource,
		"permission": it.Permission, "subject": it.Subject}
	var out struct {
		Permissionship string `json:"permissionship"`
	}
	if err := postJSON(ctx, c.API.Client, c.API.URL+"/v1/permissions/check", c.API.header(), body, &out); err != nil {
		return err
	}
	return spicePermissionship(out.Permissionship)
}

// openFGA is POST /stores/{store}/check.
func (c *Check) openFGA(ctx context.Context, rng *rand.Rand) error {
	body := map[string]any{"authorization_model_id": c.API.Model, "consistency": c.API.fgaConsistency(),
		"tuple_key": map[string]string{"user": c.Keys.subject(rng), "relation": c.Permission, "object": c.Keys.resource(rng)}}
	var out struct {
		Allowed *bool `json:"allowed"`
	}
	if err := postJSON(ctx, c.API.Client, c.API.fgaPath("check"), c.API.header(), body, &out); err != nil {
		return err
	}
	if out.Allowed == nil {
		return errors.New("openfga check answer has no allowed field")
	}
	return nil
}

// spiceDB is POST /v1/permissions/checkbulk (CheckBulkPermissions). Every
// item must come back as a pair, in order, for the resource asked about,
// with a permissionship and no error.
func (b *BulkCheck) spiceDB(ctx context.Context, rng *rand.Rand) error {
	items := make([]spiceItem, b.Items)
	for i := range items {
		items[i] = b.Keys.spiceItem(rng, b.Permission)
	}
	var out struct {
		Pairs []struct {
			Request struct {
				Resource spiceObject `json:"resource"`
			} `json:"request"`
			Item *struct {
				Permissionship string `json:"permissionship"`
			} `json:"item"`
			Error *spiceError `json:"error"`
		} `json:"pairs"`
	}
	body := map[string]any{"consistency": b.API.spiceConsistency(), "items": items}
	if err := postJSON(ctx, b.API.Client, b.API.URL+"/v1/permissions/checkbulk", b.API.header(), body, &out); err != nil {
		return err
	}
	if len(out.Pairs) != len(items) {
		return fmt.Errorf("bulk check answered %d of %d items", len(out.Pairs), len(items))
	}
	for i, p := range out.Pairs {
		switch {
		case p.Error != nil:
			return fmt.Errorf("bulk check item %d: code %d: %s", i, p.Error.Code, p.Error.Message)
		case p.Request.Resource != items[i].Resource:
			return fmt.Errorf("bulk check item %d answers %s:%s, asked %s:%s", i,
				p.Request.Resource.Type, p.Request.Resource.ID, items[i].Resource.Type, items[i].Resource.ID)
		case p.Item == nil:
			return fmt.Errorf("bulk check item %d has neither item nor error", i)
		}
		if err := spicePermissionship(p.Item.Permissionship); err != nil {
			return fmt.Errorf("bulk check item %d: %w", i, err)
		}
	}
	return nil
}

// openFGA is POST /stores/{store}/batch-check, each check named by its
// position as its correlation ID. Every ID must be answered, with allowed
// and no error.
func (b *BulkCheck) openFGA(ctx context.Context, rng *rand.Rand) error {
	type check struct {
		Tuple map[string]string `json:"tuple_key"`
		ID    string            `json:"correlation_id"`
	}
	checks := make([]check, b.Items)
	for i := range checks {
		checks[i] = check{map[string]string{"user": b.Keys.subject(rng), "relation": b.Permission,
			"object": b.Keys.resource(rng)}, strconv.Itoa(i)}
	}
	var out struct {
		Result map[string]struct {
			Allowed *bool `json:"allowed"`
			Error   *struct {
				InputError    string `json:"input_error"`
				InternalError string `json:"internal_error"`
				Message       string `json:"message"`
			} `json:"error"`
		} `json:"result"`
	}
	body := map[string]any{"authorization_model_id": b.API.Model, "consistency": b.API.fgaConsistency(), "checks": checks}
	if err := postJSON(ctx, b.API.Client, b.API.fgaPath("batch-check"), b.API.header(), body, &out); err != nil {
		return err
	}
	if len(out.Result) != len(checks) {
		return fmt.Errorf("bulk check answered %d of %d items", len(out.Result), len(checks))
	}
	for _, c := range checks {
		r, ok := out.Result[c.ID]
		switch {
		case !ok:
			return fmt.Errorf("bulk check item %s is not answered", c.ID)
		case r.Error != nil:
			return fmt.Errorf("bulk check item %s: %s", c.ID, r.Error.Message)
		case r.Allowed == nil:
			return fmt.Errorf("bulk check item %s has no allowed field", c.ID)
		}
	}
	return nil
}

// within checks a lookup answer's size against Limit.
func (l *Lookup) within(n int) error {
	if l.Limit > 0 && n > l.Limit {
		return fmt.Errorf("lookup answered %d resources, over the limit of %d", n, l.Limit)
	}
	return nil
}

// spiceDB is POST /v1/permissions/resources (LookupResources) with
// optionalLimit Limit. The gateway streams one JSON object a line, each a
// result or an error; every result must name a resource ID with a
// has-permission answer, and the stream must end without an error.
func (l *Lookup) spiceDB(ctx context.Context, rng *rand.Rand) error {
	body := map[string]any{"consistency": l.API.spiceConsistency(), "resourceObjectType": l.Keys.ResourceType,
		"permission": l.Permission, "subject": spiceSubject{spiceObject{l.Keys.SubjectType, l.Keys.subjectID(rng)}}}
	if l.Limit > 0 {
		body["optionalLimit"] = l.Limit
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.API.URL+"/v1/permissions/resources", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header = l.API.header()
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.API.Client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		_, err := readAnswer(resp, http.StatusOK)
		return err
	}
	defer resp.Body.Close()
	return l.spiceStream(resp.Body)
}

// spiceStream reads a LookupResources answer stream.
func (l *Lookup) spiceStream(r io.Reader) error {
	sc := bufio.NewScanner(io.LimitReader(r, maxBody))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	n := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var msg struct {
			Result *struct {
				ID             string `json:"resourceObjectId"`
				Permissionship string `json:"permissionship"`
			} `json:"result"`
			Error *spiceError `json:"error"`
		}
		if err := json.Unmarshal(line, &msg); err != nil {
			return fmt.Errorf("lookup answer is not the expected JSON stream: %w", err)
		}
		switch {
		case msg.Error != nil:
			return fmt.Errorf("lookup stream: code %d: %s", msg.Error.Code, msg.Error.Message)
		case msg.Result == nil || msg.Result.ID == "":
			return errors.New("lookup stream has a message with no resource")
		case msg.Result.Permissionship != "LOOKUP_PERMISSIONSHIP_HAS_PERMISSION":
			return fmt.Errorf("lookup answered %s for %s", msg.Result.Permissionship, msg.Result.ID)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("lookup stream: %w", err)
	}
	return l.within(n)
}

// openFGA is POST /stores/{store}/list-objects. ListObjects has no limit
// in the request: the server's --listObjects-max-results bounds it, and
// the answer must stay within Limit, so a server set higher than the
// other products' limit fails instead of being compared unfairly. Every
// object must be of ResourceType.
func (l *Lookup) openFGA(ctx context.Context, rng *rand.Rand) error {
	body := map[string]any{"authorization_model_id": l.API.Model, "consistency": l.API.fgaConsistency(),
		"type": l.Keys.ResourceType, "relation": l.Permission, "user": l.Keys.subject(rng)}
	var out struct {
		Objects *[]string `json:"objects"`
	}
	if err := postJSON(ctx, l.API.Client, l.API.fgaPath("list-objects"), l.API.header(), body, &out); err != nil {
		return err
	}
	if out.Objects == nil {
		return errors.New("list objects answer has no objects")
	}
	for _, o := range *out.Objects {
		if !strings.HasPrefix(o, l.Keys.ResourceType+":") {
			return fmt.Errorf("list objects answered %q, not a %s", o, l.Keys.ResourceType)
		}
	}
	return l.within(len(*out.Objects))
}

// spiceDB is POST /v1/relationships/write of one OPERATION_TOUCH. The
// answer must carry a writtenAt token.
func (w *Write) spiceDB(ctx context.Context, rng *rand.Rand) error {
	up := map[string]any{"operation": "OPERATION_TOUCH", "relationship": map[string]any{
		"resource": spiceObject{w.Keys.ResourceType, w.Keys.resourceID(rng)}, "relation": w.Relation,
		"subject": spiceSubject{spiceObject{w.Keys.SubjectType, w.Keys.subjectID(rng)}}}}
	var out struct {
		WrittenAt struct {
			Token string `json:"token"`
		} `json:"writtenAt"`
	}
	body := map[string]any{"updates": []any{up}}
	if err := postJSON(ctx, w.API.Client, w.API.URL+"/v1/relationships/write", w.API.header(), body, &out); err != nil {
		return err
	}
	if out.WrittenAt.Token == "" {
		return errors.New("spicedb write answer has no writtenAt token")
	}
	return nil
}

// openFGA is POST /stores/{store}/write of one tuple with on_duplicate
// ignore, OpenFGA's equivalent of a touch: writing a tuple that exists
// succeeds. OpenFGA answers an empty object.
func (w *Write) openFGA(ctx context.Context, rng *rand.Rand) error {
	tuple := map[string]string{"user": w.Keys.subject(rng), "relation": w.Relation, "object": w.Keys.resource(rng)}
	body := map[string]any{"authorization_model_id": w.API.Model,
		"writes": map[string]any{"on_duplicate": "ignore", "tuple_keys": []any{tuple}}}
	var out map[string]json.RawMessage
	if err := postJSON(ctx, w.API.Client, w.API.fgaPath("write"), w.API.header(), body, &out); err != nil {
		return err
	}
	if out == nil {
		return errors.New("openfga write answer is not an object")
	}
	return nil
}
