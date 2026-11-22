package datasets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxBatch is the most updates one authz write takes.
const MaxBatch = 1000

// WriteFormat is how one product's write API takes a batch of
// relationships: the path a write is posted to, the most relationships one
// write may carry, and how its JSON body is built. Every write must be
// idempotent (a touch, or a write that ignores duplicates), so that a load
// can be retried and resumed.
type WriteFormat struct {
	Path     string
	MaxBatch int
	// Begin opens a request body, Append adds one relationship (the loader
	// puts the commas between them) and End closes the body.
	Begin  func(b []byte) []byte
	Append func(b []byte, r *Relationship) []byte
	End    func(b []byte) []byte
}

// AuthzWrites is authz's POST /v1/relationships/write of touches.
var AuthzWrites = WriteFormat{
	Path:     "/v1/relationships/write",
	MaxBatch: MaxBatch,
	Begin:    func(b []byte) []byte { return append(b, `{"updates":[`...) },
	// The tuples need no JSON escaping (see AppendOpenFGA).
	Append: func(b []byte, r *Relationship) []byte {
		b = append(b, `{"op":"touch","relationship":"`...)
		return append(r.AppendTuple(b), `"}`...)
	},
	End: func(b []byte) []byte { return append(b, "]}"...) },
}

// Loader writes a graph into a running authz through its HTTP API: the
// schema with PUT /v1/schema, then the relationships as touches with POST
// /v1/relationships/write, Batch to a request, Workers requests at a time.
// Touches are idempotent, so a load can be repeated or resumed from any
// relationship number, and a request that fails with 429 or a 5xx status
// is retried. With Format set it writes to another product's API instead
// (bench/products).
type Loader struct {
	Client *http.Client
	URL    string // base URL, such as http://127.0.0.1:8080
	Key    string // API key, sent as a bearer token
	// Format is the write API; nil is AuthzWrites.
	Format *WriteFormat
	// Batch is the number of updates per write, 1 to the format's MaxBatch
	// (0: its MaxBatch).
	Batch int
	// Workers is the number of writes in flight (0: 4).
	Workers int
	// Retries is how often one write is retried (0: 5), with backoff from
	// 50 ms doubling to at most 2 s.
	Retries int
	// Progress, when set, is called after each write with the number of
	// relationships written so far. It may be called from several
	// goroutines at once.
	Progress func(written int64)
}

// LoadResult is what a load wrote.
type LoadResult struct {
	Relationships int64         `json:"relationships"`
	Writes        int64         `json:"writes"`
	Retries       int64         `json:"retries"`
	Elapsed       time.Duration `json:"elapsed_ns"`
}

// PerSecond is the load's rate in relationships per second.
func (r LoadResult) PerSecond() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(r.Relationships) / r.Elapsed.Seconds()
}

// PutSchema writes schema.
func (l *Loader) PutSchema(ctx context.Context, schema string) error {
	body, _ := json.Marshal(map[string]string{"schema": schema})
	_, err := l.Call(ctx, http.MethodPut, "/v1/schema", body)
	return err
}

// Call makes one request with the loader's key and retries, and returns
// the 2xx answer's body. Products use it for their setup calls.
func (l *Loader) Call(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	_, answer, err := l.send(ctx, method, path, body)
	return answer, err
}

// Load writes the relationships numbered from..to-1 of g.
func (l *Loader) Load(ctx context.Context, g Graph, from, to int64) (LoadResult, error) {
	format := l.Format
	if format == nil {
		format = &AuthzWrites
	}
	batch, workers := l.Batch, l.Workers
	if batch == 0 {
		batch = format.MaxBatch
	}
	if workers == 0 {
		workers = 4
	}
	if batch < 1 || batch > format.MaxBatch || workers < 1 {
		return LoadResult{}, fmt.Errorf("load: batch %d (want 1 to %d) and workers %d (want at least 1)", batch, format.MaxBatch, workers)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	start := time.Now()
	type write struct {
		body []byte
		n    int
	}
	bodies := make(chan write, workers)
	var written, writes, retries atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for wr := range bodies {
				n, _, err := l.send(ctx, http.MethodPost, format.Path, wr.body)
				retries.Add(int64(n))
				if err != nil {
					cancel(err)
					continue
				}
				writes.Add(1)
				w := written.Add(int64(wr.n))
				if l.Progress != nil {
					l.Progress(w)
				}
			}
		}()
	}
	// Build each request body directly, without encoding/json.
	var buf []byte
	inBatch := 0
	flush := func() error {
		if inBatch == 0 {
			return nil
		}
		buf = format.End(buf)
		select {
		case bodies <- write{buf, inBatch}:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
		buf, inBatch = nil, 0
		return nil
	}
	err := g.EachRange(from, to, func(r *Relationship) error {
		if inBatch == 0 {
			buf = format.Begin(make([]byte, 0, batch*48+256))
		} else {
			buf = append(buf, ',')
		}
		buf = format.Append(buf, r)
		if inBatch++; inBatch == batch {
			return flush()
		}
		return nil
	})
	if err == nil {
		err = flush()
	}
	close(bodies)
	wg.Wait()
	if cause := context.Cause(ctx); err == nil && cause != nil {
		err = cause
	}
	res := LoadResult{Relationships: written.Load(), Writes: writes.Load(), Retries: retries.Load(), Elapsed: time.Since(start)}
	return res, err
}

// errStatus is an answer that is not 2xx.
type errStatus struct {
	status int
	body   string
}

func (e *errStatus) Error() string { return fmt.Sprintf("status %d: %s", e.status, e.body) }

func retryable(err error) bool {
	var es *errStatus
	if errors.As(err, &es) {
		return es.status == http.StatusTooManyRequests || es.status >= 500
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// send makes one request, retrying it, and returns the number of retries
// and the answer.
func (l *Loader) send(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	tries := l.Retries
	if tries == 0 {
		tries = 5
	}
	wait := 50 * time.Millisecond
	for n := 0; ; n++ {
		answer, err := l.once(ctx, method, path, body)
		if err == nil || n == tries || !retryable(err) || ctx.Err() != nil {
			if err != nil {
				err = fmt.Errorf("%s %s: %w", method, path, err)
			}
			return n, answer, err
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return n, nil, fmt.Errorf("%s %s: %w", method, path, context.Cause(ctx))
		}
		wait = min(wait*2, 2*time.Second)
	}
}

// maxAnswer is the most of an answer once keeps: setup answers (a store,
// a model ID) are small, and an error body only needs its start.
const maxAnswer = 1 << 20

func (l *Loader) once(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(l.URL, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+l.Key)
	c := l.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if resp.StatusCode/100 != 2 {
		return nil, &errStatus{resp.StatusCode, strings.TrimSpace(string(b[:min(len(b), 4<<10)]))}
	}
	return b, err
}
