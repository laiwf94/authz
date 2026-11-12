package keys_test

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/clock"
	"github.com/laiwf94/authz/internal/platform/jose"
	"github.com/laiwf94/authz/internal/platform/keys"
	"github.com/laiwf94/authz/internal/platform/seal"
)

// tracks is everything one process signs, seals and verifies with, built
// on the four rings of one key set: session cookies (sign-on), upstream
// JWTs (sign-on), consistency tokens (authorization) and agent tokens
// (agent gateway).
type tracks struct {
	set     *keys.Set
	cookies *seal.Keyring
	tokens  *token.Issuer
	agents  *identity.Authenticator
	jwks    atomic.Pointer[jose.KeySet] // the upstream keys as published
}

// newTracks builds the consumers on set, refusing a set that lacks a ring
// or holds a ring of the wrong algorithm, as a process starting or
// reloading from a ring file must.
func newTracks(set *keys.Set, now func() time.Time) (*tracks, error) {
	for _, name := range []string{keys.RingSession, keys.RingUpstream, keys.RingConsistency, keys.RingAgent} {
		if set.Ring(name) == nil {
			return nil, fmt.Errorf("no %s ring", name)
		}
	}
	if a := set.Ring(keys.RingUpstream).Alg(); a != keys.ES256 {
		return nil, fmt.Errorf("upstream ring holds %s keys", a)
	}
	tr := &tracks{set: set}
	var err error
	if tr.cookies, err = seal.FromRing(set.Ring(keys.RingSession), now); err != nil {
		return nil, err
	}
	if tr.tokens, err = token.FromRing(set.Ring(keys.RingConsistency), now); err != nil {
		return nil, err
	}
	if tr.agents, err = identity.New(identity.Config{Ring: set.Ring(keys.RingAgent),
		Issuer: "authz", Audience: "authz-mcp", Now: now}); err != nil {
		return nil, err
	}
	return tr, tr.publish(now())
}

// publish renders the JWKS, as the gateway serves it to upstreams.
func (tr *tracks) publish(now time.Time) error {
	ks, err := jose.ParseKeySet(tr.set.JWKS(now))
	if err != nil {
		return err
	}
	tr.jwks.Store(ks)
	return nil
}

// issued is one credential of each kind, with the time it was issued.
type issued struct {
	at       time.Time
	cookie   string
	rev      store.Revision
	consist  string
	agent    string
	upstream string
}

func (tr *tracks) issue(at time.Time, n uint64) (issued, error) {
	in := issued{at: at, rev: store.Revision(n)}
	in.cookie = tr.cookies.Seal("session", fmt.Appendf(nil, "s%d", n))
	in.consist = tr.tokens.Encode(in.rev)
	var err error
	if in.agent, err = tr.agents.Mint("agent-1", "owner", []string{"files:read"}, time.Hour); err != nil {
		return in, err
	}
	k := tr.set.Ring(keys.RingUpstream).Current()
	sg, err := jose.NewSigner(k.Signer().(*ecdsa.PrivateKey))
	if err != nil {
		return in, err
	}
	if sg.KeyID() != k.ID() {
		return in, fmt.Errorf("upstream kid %s, ring kid %s", sg.KeyID(), k.ID())
	}
	in.upstream, err = sg.Sign(map[string]any{"sub": "user", "n": n})
	return in, err
}

// verify checks each credential and returns the kinds that failed.
func (tr *tracks) verify(in issued, n uint64) []string {
	var bad []string
	if pt, err := tr.cookies.Open("session", in.cookie); err != nil || string(pt) != fmt.Sprintf("s%d", n) {
		bad = append(bad, "session cookie")
	}
	if rev, err := tr.tokens.Decode(in.consist); err != nil || rev != in.rev {
		bad = append(bad, "consistency token")
	}
	if id, err := tr.agents.Authenticate(in.agent); err != nil || id.AgentID != "agent-1" {
		bad = append(bad, "agent token")
	}
	if !upstreamVerifies(tr.jwks.Load(), in.upstream) {
		bad = append(bad, "upstream JWT")
	}
	return bad
}

func upstreamVerifies(ks *jose.KeySet, tok string) bool {
	t, err := jose.Parse(tok)
	if err != nil {
		return false
	}
	for _, k := range ks.Keys {
		if k.ID == t.Header.Kid {
			return t.Verify(k, []string{"ES256"}) == nil
		}
	}
	return false
}

// replica follows the primary's ring file: it reloads after every save,
// refuses a file that does not load or does not hold usable rings, and
// keeps the keys it had.
type replica struct {
	path    string
	now     func() time.Time
	cur     atomic.Pointer[tracks]
	refused int
}

func (rp *replica) reload() error {
	set, err := keys.Load(rp.path)
	if err == nil {
		var tr *tracks
		if tr, err = newTracks(set, rp.now); err == nil {
			rp.cur.Store(tr)
			return nil
		}
	}
	rp.refused++
	return err
}

// Credentials of all three tracks, issued by eight goroutines while every
// ring rotates on schedule, verify in the issuing process and in a replica
// that reloads the ring file, as long as they are younger than the
// overlap. The replica refuses each broken version of the file and keeps
// verifying with the keys it had. Once the overlap of the first keys has
// ended, the credentials they signed are refused everywhere.
func TestRotationAcrossTracksUnderLoad(t *testing.T) {
	const (
		rotateEvery = time.Second
		overlap     = 3 * time.Second
		step        = 250 * time.Millisecond
		steps       = 48 // 12 rotations of every ring
		workers     = 8
		perStep     = 2 * workers
	)
	clk := clock.NewFake(time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC))
	now := clk.Now
	pol := keys.Policy{RotateEvery: rotateEvery, Overlap: overlap}
	set := keys.NewSet()
	for name, alg := range map[string]keys.Alg{keys.RingSession: keys.A256GCM, keys.RingUpstream: keys.ES256,
		keys.RingConsistency: keys.HS256, keys.RingAgent: keys.HS256} {
		r, err := keys.NewRing(alg, pol, now())
		if err != nil {
			t.Fatal(err)
		}
		if err := set.Add(name, r); err != nil {
			t.Fatal(err)
		}
	}
	primary, err := newTracks(set, now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := set.Save(path); err != nil {
		t.Fatal(err)
	}
	rp := &replica{path: path, now: now}
	if err := rp.reload(); err != nil {
		t.Fatal(err)
	}

	// The first credentials, kept to check they expire at the end.
	first, err := primary.issue(now(), 0)
	if err != nil {
		t.Fatal(err)
	}

	var (
		stop     atomic.Bool
		ops      atomic.Int64
		checked  atomic.Int64
		crossed  atomic.Int64 // verifications of credentials older than the last rotation
		rotated  atomic.Int64 // when the rings last rotated, in Unix nanoseconds
		mu       sync.Mutex
		failures []string
		wg       sync.WaitGroup
		serial   atomic.Uint64
	)
	fail := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if len(failures) < 20 {
			failures = append(failures, fmt.Sprintf(format, args...))
		}
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			type held struct {
				in issued
				n  uint64
			}
			var hold []held
			for !stop.Load() {
				n := serial.Add(1)
				// The time is read before signing: the key that signs
				// was current at or after it, so it verifies until at
				// least at+overlap.
				in, err := primary.issue(now(), n)
				if err != nil {
					fail("issue: %v", err)
					return
				}
				hold = append(hold, held{in, n})
				if len(hold) > 24 {
					hold = hold[1:]
				}
				for _, h := range hold {
					for name, tr := range map[string]*tracks{"primary": primary, "replica": rp.cur.Load()} {
						bad := tr.verify(h.in, h.n)
						// The time is read after verifying: only a
						// credential younger than the overlap then must
						// have verified.
						if age := now().Sub(h.in.at); len(bad) > 0 && age < overlap {
							fail("%s: %v refused at age %s", name, bad, age)
						}
						checked.Add(1)
						if h.in.at.UnixNano() < rotated.Load() {
							crossed.Add(1)
						}
					}
				}
				ops.Add(1)
			}
		}()
	}

	broken := brokenFiles(t, set, now())
	rotations := 0
	for i := 0; i < steps; i++ {
		clk.Advance(step)
		changed, err := set.Tick(now())
		if err != nil {
			t.Fatal(err)
		}
		if len(changed) > 0 {
			for _, name := range changed {
				if name == keys.RingConsistency {
					rotations++
					rotated.Store(now().UnixNano())
				}
			}
			// What a keys.Scheduler's OnChange does: publish and save.
			if err := primary.publish(now()); err != nil {
				t.Fatal(err)
			}
			if err := set.Save(path); err != nil {
				t.Fatal(err)
			}
			if err := rp.reload(); err != nil {
				t.Fatalf("replica refused a good file: %v", err)
			}
		}
		// Every other step, an operator's broken edit lands on the file:
		// refused, the replica keeps its keys, then the good file is back.
		if i%2 == 1 {
			b := broken[i/2%len(broken)]
			before := rp.cur.Load()
			if err := os.WriteFile(path, b.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := rp.reload(); err == nil {
				t.Fatalf("replica accepted a broken file (%s)", b.name)
			}
			if rp.cur.Load() != before {
				t.Fatalf("replica changed keys on a broken file (%s)", b.name)
			}
			if err := set.Save(path); err != nil {
				t.Fatal(err)
			}
		}
		for start := ops.Load(); ops.Load() < start+perStep && !stopped(&mu, &failures); {
			time.Sleep(100 * time.Microsecond)
		}
	}
	stop.Store(true)
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("%d+ failures, first: %s", len(failures), bytes.Join(toBytes(failures), []byte("\n")))
	}
	if rotations < steps*int(step)/int(rotateEvery)-1 {
		t.Fatalf("only %d rotations", rotations)
	}
	if crossed.Load() == 0 {
		t.Fatal("no credential was verified across a rotation")
	}
	t.Logf("%d issues of 4 credentials, %d verifications of all 4 in two processes (%d across a rotation), %d rotations per ring, %d broken files refused, 0 failures",
		ops.Load(), checked.Load(), crossed.Load(), rotations, rp.refused)

	// The first keys' overlap has long ended; their credentials are refused
	// in both processes, though the ring file may still list them until a
	// prune.
	for name, tr := range map[string]*tracks{"primary": primary, "replica": rp.cur.Load()} {
		if bad := tr.verify(first, 0); len(bad) != 4 {
			t.Errorf("%s: only %v of the first credentials refused", name, bad)
		}
	}
}

func stopped(mu *sync.Mutex, f *[]string) bool {
	mu.Lock()
	defer mu.Unlock()
	return len(*f) > 0
}

func toBytes(ss []string) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = []byte(s)
	}
	return out
}

type brokenFile struct {
	name string
	data []byte
}

// brokenFiles are the edits a replica must refuse: files that do not
// load, and files that load but can't serve the tracks.
func brokenFiles(t *testing.T, set *keys.Set, now time.Time) []brokenFile {
	t.Helper()
	good, err := set.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func(rings []any)) []byte {
		var d map[string]any
		_ = json.Unmarshal(good, &d)
		f(d["rings"].([]any))
		b, _ := json.Marshal(d)
		return b
	}
	// An ES256 key id is the key's thumbprint; a hand-edited one is
	// refused. (Secret keys keep any name they are given.)
	tampered := edit(func(rs []any) {
		for _, r := range rs {
			if r.(map[string]any)["name"] == keys.RingUpstream {
				r.(map[string]any)["current"].(map[string]any)["kid"] = "not-the-thumbprint"
			}
		}
	})
	var d map[string]any
	_ = json.Unmarshal(good, &d)
	var kept []any
	for _, r := range d["rings"].([]any) {
		if r.(map[string]any)["name"] != keys.RingSession {
			kept = append(kept, r)
		}
	}
	d["rings"] = kept
	missing, _ := json.Marshal(d)
	// A session ring of HMAC keys: a valid file the cookies can't use.
	wrong := keys.NewSet()
	for _, name := range set.Names() {
		r := set.Ring(name)
		if name == keys.RingSession {
			if r, err = keys.NewRing(keys.HS256, r.Policy(), now); err != nil {
				t.Fatal(err)
			}
		}
		if err := wrong.Add(name, r); err != nil {
			t.Fatal(err)
		}
	}
	wrongAlg, err := wrong.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	future := edit(func([]any) {})
	future = bytes.Replace(future, []byte(`"version":1`), []byte(`"version":2`), 1)
	for name, b := range map[string][]byte{"tampered": tampered, "future": future} {
		if _, err := keys.Unmarshal(b); err == nil {
			t.Fatalf("%s file loads", name)
		}
	}
	// These two load; newTracks is what refuses them.
	for name, b := range map[string][]byte{"missing": missing, "wrong algorithm": wrongAlg} {
		if _, err := keys.Unmarshal(b); err != nil {
			t.Fatalf("%s file: %v", name, err)
		}
	}
	return []brokenFile{
		{"truncated", good[:len(good)/2]},
		{"empty", nil},
		{"not JSON", []byte("rotate me\n")},
		{"tampered key id", tampered},
		{"newer version", future},
		{"no session ring", missing},
		{"HMAC session ring", wrongAlg},
	}
}
