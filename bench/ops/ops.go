// Package ops holds the requests the benchmark offers: checks, bulk checks,
// lookups and writes against the authorization API, forward-auth decisions,
// whole OpenID Connect logins through a browser-style form flow, and MCP
// tools/call requests. Each is a load.Op, safe for concurrent use by the
// load generator's workers, and checks the answer as well as the status, so
// a server that answers quickly with the wrong thing is counted as failing.
package ops

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// NewClient returns an HTTP client for workers concurrent requests: keeps
// one idle connection per worker, never follows redirects (operations that
// need to do it themselves), and trusts the PEM file caFile in addition to
// the system roots when it is not empty.
func NewClient(workers int, caFile string) (*http.Client, error) {
	tr := &http.Transport{
		Proxy:               nil, // the benchmark measures the server, never a proxy in between
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        workers,
		MaxIdleConnsPerHost: workers,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no PEM certificates", caFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, CheckRedirect: noRedirect}, nil
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// StatusError is an answer with an unexpected status.
type StatusError struct {
	Status int
	Body   string // the first 200 bytes
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("status %d", e.Status)
	}
	return fmt.Sprintf("status %d: %s", e.Status, e.Body)
}

// maxBody bounds what an operation reads from an answer.
const maxBody = 4 << 20

// readAnswer reads resp's body and returns it if the status is want; it
// always closes the body.
func readAnswer(resp *http.Response, want int) ([]byte, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != want {
		if len(b) > 200 {
			b = b[:200]
		}
		return nil, &StatusError{Status: resp.StatusCode, Body: string(bytes.TrimSpace(b))}
	}
	return b, nil
}

// postJSON sends body to url with the headers and decodes a want-status
// answer into out.
func postJSON(ctx context.Context, c *http.Client, url string, hdr http.Header, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	b, err := readAnswer(resp, http.StatusOK)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("answer is not the expected JSON: %w", err)
	}
	return nil
}

// Keyspace names the objects requests are about: resources are
// ResourceType:ResourcePrefix<n> for n in [0, Resources), subjects
// SubjectType:SubjectPrefix<n> for n in [0, Subjects). With Zipf above 1,
// lower numbers are drawn more often, a Zipf distribution of that exponent
// (hot documents and busy users); otherwise every number is equally likely.
type Keyspace struct {
	ResourceType, ResourcePrefix string
	Resources                    int
	SubjectType, SubjectPrefix   string
	Subjects                     int
	Zipf                         float64
}

// Validate reports a keyspace no request can be drawn from.
func (k Keyspace) Validate() error {
	if k.ResourceType == "" || k.SubjectType == "" {
		return errors.New("keyspace: resource and subject types are required")
	}
	if k.Resources <= 0 || k.Subjects <= 0 {
		return errors.New("keyspace: resource and subject counts must be positive")
	}
	if k.Zipf != 0 && k.Zipf <= 1 {
		return fmt.Errorf("keyspace: zipf exponent %v, want 0 (uniform) or above 1", k.Zipf)
	}
	return nil
}

// draw returns a number in [0, n), uniform or Zipf-distributed.
func (k Keyspace) draw(rng *rand.Rand, n int) int {
	if k.Zipf == 0 || n == 1 {
		return rng.IntN(n)
	}
	return zipf(rng, k.Zipf, n)
}

// zipfs holds one Zipf generator per worker source, exponent and size: a
// rand.Zipf is bound to the source it draws from, and every worker has its
// own, so after the first draw a lookup here is all a request pays.
var zipfs sync.Map // zipfKey -> *rand.Zipf

type zipfKey struct {
	rng *rand.Rand
	s   float64
	n   int
}

// zipf draws from [0, n) with P(i) proportional to 1/(i+1)^s, by the
// standard library's rejection-inversion, which needs no table and so works
// for a hundred million objects as well as for ten.
func zipf(rng *rand.Rand, s float64, n int) int {
	key := zipfKey{rng, s, n}
	z, ok := zipfs.Load(key)
	if !ok {
		z, _ = zipfs.LoadOrStore(key, rand.NewZipf(rng, s, 1, uint64(n-1)))
	}
	return int(z.(*rand.Zipf).Uint64())
}

func (k Keyspace) resource(rng *rand.Rand) string {
	return k.ResourceType + ":" + k.resourceID(rng)
}

func (k Keyspace) subject(rng *rand.Rand) string {
	return k.SubjectType + ":" + k.subjectID(rng)
}

// resourceID and subjectID are the ID parts alone, for APIs that take an
// object's type and ID apart.
func (k Keyspace) resourceID(rng *rand.Rand) string {
	return k.ResourcePrefix + strconv.Itoa(k.draw(rng, k.Resources))
}

func (k Keyspace) subjectID(rng *rand.Rand) string {
	return k.SubjectPrefix + strconv.Itoa(k.draw(rng, k.Subjects))
}

// API is an authorization API server: its base URL and key, and which
// product's API it speaks. Check, BulkCheck, Lookup and Write ask the same
// question of any of them, each in the product's own requests (see
// products.go), so one mix measures authz, SpiceDB and OpenFGA alike.
type API struct {
	Client *http.Client
	URL    string // base URL, without /v1
	Key    string // sent as a bearer token by every product
	// Consistency is the mode reads ask for, in authz's names; empty means
	// minimize_latency. SpiceDB and OpenFGA take minimize_latency and
	// fully_consistent, translated by Validate's rules.
	Consistency string
	// Product is the API spoken: ProductAuthz (the default when empty),
	// ProductSpiceDB (its HTTP gateway) or ProductOpenFGA.
	Product string
	// Store and Model are the OpenFGA store and authorization model IDs
	// every OpenFGA request names.
	Store, Model string
}

func (a *API) header() http.Header {
	return http.Header{"Authorization": {"Bearer " + a.Key}}
}

func (a *API) consistency() map[string]string {
	if a.Consistency == "" {
		return map[string]string{"mode": "minimize_latency"}
	}
	return map[string]string{"mode": a.Consistency}
}

// Check is POST /v1/check of Permission on a drawn resource for a drawn
// subject. The answer must carry a boolean "allowed".
type Check struct {
	API        *API
	Keys       Keyspace
	Permission string
}

// Name implements load.Op.
func (*Check) Name() string { return "check" }

// Do implements load.Op.
func (c *Check) Do(ctx context.Context, _ int, rng *rand.Rand) error {
	switch c.API.Product {
	case ProductSpiceDB:
		return c.spiceDB(ctx, rng)
	case ProductOpenFGA:
		return c.openFGA(ctx, rng)
	}
	var out struct {
		Allowed *bool `json:"allowed"`
	}
	body := map[string]any{"resource": c.Keys.resource(rng), "permission": c.Permission,
		"subject": c.Keys.subject(rng), "consistency": c.API.consistency()}
	if err := postJSON(ctx, c.API.Client, c.API.URL+"/v1/check", c.API.header(), body, &out); err != nil {
		return err
	}
	if out.Allowed == nil {
		return errors.New("check answer has no allowed field")
	}
	return nil
}

// BulkCheck is POST /v1/check/bulk of Items drawn checks. Every item must be
// answered, in order, without an item error.
type BulkCheck struct {
	API        *API
	Keys       Keyspace
	Permission string
	Items      int
}

// Name implements load.Op.
func (*BulkCheck) Name() string { return "bulk_check" }

// Do implements load.Op.
func (b *BulkCheck) Do(ctx context.Context, _ int, rng *rand.Rand) error {
	switch b.API.Product {
	case ProductSpiceDB:
		return b.spiceDB(ctx, rng)
	case ProductOpenFGA:
		return b.openFGA(ctx, rng)
	}
	items := make([]map[string]string, b.Items)
	for i := range items {
		items[i] = map[string]string{"resource": b.Keys.resource(rng), "permission": b.Permission, "subject": b.Keys.subject(rng)}
	}
	var out struct {
		Results []struct {
			Allowed *bool  `json:"allowed"`
			Error   string `json:"error"`
		} `json:"results"`
	}
	body := map[string]any{"items": items, "consistency": b.API.consistency()}
	if err := postJSON(ctx, b.API.Client, b.API.URL+"/v1/check/bulk", b.API.header(), body, &out); err != nil {
		return err
	}
	if len(out.Results) != len(items) {
		return fmt.Errorf("bulk check answered %d of %d items", len(out.Results), len(items))
	}
	for i, r := range out.Results {
		if r.Error != "" {
			return fmt.Errorf("bulk check item %d: %s", i, r.Error)
		}
		if r.Allowed == nil {
			return fmt.Errorf("bulk check item %d has no allowed field", i)
		}
	}
	return nil
}

// Lookup is POST /v1/lookup/resources: the ResourceType resources a drawn
// subject has Permission on, up to Limit (0 for the server's default). An
// answer with more than Limit resources fails.
type Lookup struct {
	API        *API
	Keys       Keyspace
	Permission string
	Limit      int
}

// Name implements load.Op.
func (*Lookup) Name() string { return "lookup" }

// Do implements load.Op.
func (l *Lookup) Do(ctx context.Context, _ int, rng *rand.Rand) error {
	switch l.API.Product {
	case ProductSpiceDB:
		return l.spiceDB(ctx, rng)
	case ProductOpenFGA:
		return l.openFGA(ctx, rng)
	}
	var out struct {
		IDs *[]string `json:"resource_ids"`
	}
	body := map[string]any{"resource_type": l.Keys.ResourceType, "permission": l.Permission,
		"subject": l.Keys.subject(rng), "consistency": l.API.consistency()}
	if l.Limit > 0 {
		body["limit"] = l.Limit
	}
	if err := postJSON(ctx, l.API.Client, l.API.URL+"/v1/lookup/resources", l.API.header(), body, &out); err != nil {
		return err
	}
	if out.IDs == nil {
		return errors.New("lookup answer has no resource_ids")
	}
	return l.within(len(*out.IDs))
}

// Write is POST /v1/relationships/write of one touch: a drawn resource's
// Relation to a drawn subject. The answer must carry a written_at token.
type Write struct {
	API      *API
	Keys     Keyspace
	Relation string
}

// Name implements load.Op.
func (*Write) Name() string { return "write" }

// Do implements load.Op.
func (w *Write) Do(ctx context.Context, _ int, rng *rand.Rand) error {
	switch w.API.Product {
	case ProductSpiceDB:
		return w.spiceDB(ctx, rng)
	case ProductOpenFGA:
		return w.openFGA(ctx, rng)
	}
	rel := w.Keys.resource(rng) + "#" + w.Relation + "@" + w.Keys.subject(rng)
	var out struct {
		WrittenAt string `json:"written_at"`
	}
	body := map[string]any{"updates": []map[string]string{{"op": "touch", "relationship": rel}}}
	if err := postJSON(ctx, w.API.Client, w.API.URL+"/v1/relationships/write", w.API.header(), body, &out); err != nil {
		return err
	}
	if out.WrittenAt == "" {
		return errors.New("write answer has no written_at")
	}
	return nil
}
