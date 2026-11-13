//go:build unix

package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/cmd/authz/internal/part"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/keys"
)

// fastAgent rotates the agent ring every second and keeps retired keys for
// 4 s.
var fastAgent = keys.Policy{RotateEvery: time.Second, Overlap: 4 * time.Second}

func TestKeysFileVariables(t *testing.T) {
	s := newSetup(t)
	c, err := loadConfig(s.getenv)
	if err != nil || c.keysFile != "" || c.signingPol != DefaultSigningPolicy {
		t.Fatalf("unset: %+v %v", c, err)
	}
	s.env["TOOLGATE_KEYS_FILE"] = "/var/lib/authz/keys.json"
	s.env["TOOLGATE_SIGNING_ROTATE_EVERY"] = "1h"
	s.env["TOOLGATE_SIGNING_OVERLAP"] = "3h"
	if c, err = loadConfig(s.getenv); err != nil || c.keysFile != "/var/lib/authz/keys.json" ||
		c.signingPol != (keys.Policy{RotateEvery: time.Hour, Overlap: 3 * time.Hour}) {
		t.Fatalf("set: %+v %v", c, err)
	}
	s.env["TOOLGATE_SIGNING_ROTATE_EVERY"], s.env["TOOLGATE_SIGNING_OVERLAP"] = "0", "0s"
	if c, err = loadConfig(s.getenv); err != nil || c.signingPol != (keys.Policy{}) {
		t.Fatalf("never rotating: %+v %v", c.signingPol, err)
	}
	for kv, want := range map[[2]string]string{
		{"TOOLGATE_SIGNING_ROTATE_EVERY", "daily"}: `"daily" is not a duration such as 24h`,
		{"TOOLGATE_SIGNING_OVERLAP", "-1h"}:        `"-1h" is not a duration`,
		{"TOOLGATE_SIGNING_ROTATE_EVERY", "1ms"}:   "rotation period 1ms is shorter than 1s",
		{"TOOLGATE_SIGNING_ROTATE_EVERY", "1h"}:    "needs an overlap",
	} {
		env := maps.Clone(s.env)
		env[kv[0]] = kv[1]
		_, err := loadConfig(func(k string) string { return env[k] })
		if err == nil || !strings.HasPrefix(err.Error(), "TOOLGATE_SIGNING_ROTATE_EVERY, TOOLGATE_SIGNING_OVERLAP: ") ||
			!strings.Contains(err.Error(), want) {
			t.Errorf("%s=%s: %v, want %q", kv[0], kv[1], err, want)
		}
	}
	// Each has its AUTHZ_MCP_ name too.
	env, err := compatEnv(func(k string) string {
		return map[string]string{"AUTHZ_MCP_KEYS_FILE": "/k.json", "AUTHZ_MCP_SIGNING_OVERLAP": "2h"}[k]
	}, gatewayEnv)
	if err != nil || env("TOOLGATE_KEYS_FILE") != "/k.json" || env("TOOLGATE_SIGNING_OVERLAP") != "2h" {
		t.Fatalf("AUTHZ_MCP_ names: %v", err)
	}
	// Toolgate's key id rule is kept.
	s.env["TOOLGATE_SIGNING_KEYS"] = strings.Repeat("k", 33) + "=" + signingKey
	if _, err := loadConfig(s.getenv); err == nil || !strings.Contains(err.Error(), "must be 1 to 32 letters") {
		t.Fatalf("long key id: %v", err)
	}
}

// The section's keys members start the gateway with what the same
// TOOLGATE_ variables give.
func TestKeysFileSectionMatchesVariables(t *testing.T) {
	dir := t.TempDir()
	kf := filepath.Join(dir, "keys.json")
	s := newSetup(t)
	s.env["TOOLGATE_KEYS_FILE"] = kf
	s.env["TOOLGATE_SIGNING_ROTATE_EVERY"], s.env["TOOLGATE_SIGNING_OVERLAP"] = "6h", "2h"
	want, err := loadConfig(s.getenv)
	if err != nil {
		t.Fatal(err)
	}
	r := mcpSchema(t, upstreamEnv).Check(goodSection(t, map[string]any{"keys_file": kf, "signing_rotate_every": "6h", "signing_overlap": "2h"}), goodEnviron)
	if len(r.Problems) != 0 {
		t.Fatal(r.Problems)
	}
	got, err := sectionConfig(pcfg.Get[Settings](r.Config, SectionName))
	if err != nil || got.keysFile != want.keysFile || got.signingPol != want.signingPol {
		t.Fatalf("section %q %+v, variables %q %+v (%v)", got.keysFile, got.signingPol, want.keysFile, want.signingPol, err)
	}
	r = mcpSchema(t, upstreamEnv).Check(goodSection(t, nil), goodEnviron)
	if got, _ := sectionConfig(pcfg.Get[Settings](r.Config, SectionName)); got.keysFile != "" || got.signingPol != DefaultSigningPolicy {
		t.Fatalf("defaults %q %+v", got.keysFile, got.signingPol)
	}
}

func TestKeysFileSectionChecks(t *testing.T) {
	dir := t.TempDir()
	wrongAlg := filepath.Join(dir, "wrong.json")
	set := keys.NewSet()
	r, _ := keys.NewRing(keys.ES256, keys.Policy{}, time.Now())
	set.Add(keys.RingAgent, r)
	if err := set.Save(wrongAlg); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage.json")
	os.WriteFile(garbage, []byte("{"), 0o600)
	src, _ := os.ReadFile(exampleConfig)
	var cfg map[string]any
	json.Unmarshal(src, &cfg)
	delete(cfg, "tokens")
	noTokens := filepath.Join(dir, "no-tokens.json")
	b, _ := json.Marshal(cfg)
	os.WriteFile(noTokens, b, 0o600)
	kf := filepath.Join(dir, "k.json")
	sc := mcpSchema(t, upstreamEnv)
	for name, c := range map[string]struct {
		extra     map[string]any
		path, msg string
		warn      bool
	}{
		"wrong alg":    {map[string]any{"keys_file": wrongAlg}, "$.mcp.keys_file", "ring agent holds ES256 keys, want HS256", false},
		"garbage":      {map[string]any{"keys_file": garbage}, "$.mcp.keys_file", garbage, false},
		"no directory": {map[string]any{"keys_file": filepath.Join(dir, "none", "k.json")}, "$.mcp.keys_file", "can't be created", false},
		"no overlap":   {map[string]any{"keys_file": kf, "signing_overlap": "0s"}, "$.mcp.signing_overlap", "needs an overlap", false},
		"long overlap": {map[string]any{"keys_file": kf, "signing_rotate_every": "1h", "signing_overlap": "20h"}, "$.mcp.signing_overlap", "longer than 15 rotation periods", false},
		"no tokens":    {map[string]any{"keys_file": kf, "config": noTokens}, "$.mcp.keys_file", "has no tokens section", false},
		// The example config allows tokens of an hour.
		"short overlap": {map[string]any{"keys_file": kf, "signing_rotate_every": "1h", "signing_overlap": "30m"}, "$.mcp.signing_overlap", "is shorter than the agents config's longest token lifetime 1h0m0s", true},
	} {
		res := sc.Check(goodSection(t, c.extra), goodEnviron)
		sev := pcfg.SeverityError
		if c.warn {
			sev = pcfg.SeverityWarning
			if res.Problems.Err() != nil {
				t.Errorf("%s: %v", name, res.Problems)
				continue
			}
		}
		if res.Problems.Count(sev) != 1 || res.Problems[0].Path != c.path || !strings.Contains(res.Problems[0].Message, c.msg) {
			t.Errorf("%s: %v, want %s: %s", name, res.Problems, c.path, c.msg)
		}
	}
	// A rotation that is never used is still checked, as the variables are.
	if res := sc.Check(goodSection(t, map[string]any{"signing_rotate_every": "1ms"}), goodEnviron); res.Problems.Err() == nil {
		t.Error("a bad rotation without keys_file was accepted")
	}
	// A good file, and one that holds the ring already.
	if res := sc.Check(goodSection(t, map[string]any{"keys_file": kf}), goodEnviron); len(res.Problems) != 0 {
		t.Fatal(res.Problems)
	}
	f, _ := keys.OpenFile(kf, nil)
	if _, err := f.Ensure(agentSpec(DefaultSigningPolicy)); err != nil {
		t.Fatal(err)
	}
	if res := sc.Check(goodSection(t, map[string]any{"keys_file": kf}), goodEnviron); len(res.Problems) != 0 {
		t.Fatal(res.Problems)
	}
}

// mintWith runs "token mint" with env changed by kv.
func mintWith(t *testing.T, s *setup, kv ...string) (string, error) {
	t.Helper()
	env := maps.Clone(s.env)
	for i := 0; i < len(kv); i += 2 {
		env[kv[i]] = kv[i+1]
	}
	var out, errb bytes.Buffer
	if code := cli(context.Background(), []string{"token", "mint", "-sub", "ci-bot", "-scope", "files:read"},
		func(k string) string { return env[k] }, nil, &out, &errb, nil); code != 0 {
		return "", &mintError{errb.String()}
	}
	return strings.TrimSpace(out.String()), nil
}

type mintError struct{ msg string }

func (e *mintError) Error() string { return e.msg }

// kidOf is the key id in a token's header.
func kidOf(t *testing.T, tok string) string {
	t.Helper()
	h, _, _ := strings.Cut(tok, ".")
	b, err := base64.RawURLEncoding.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	_, rest, _ := strings.Cut(string(b), `"kid":"`)
	kid, _, _ := strings.Cut(rest, `"`)
	return kid
}

// A gateway with a keys file starts its agent ring from the signing keys,
// so tokens they signed keep verifying, signs with the ring's current key,
// rotates it on schedule with every token verifying across the overlap,
// and refuses a token once its key's overlap ends.
func TestKeysFileSeedsAndRotates(t *testing.T) {
	s := newSetup(t)
	kf := filepath.Join(s.dir, "keys.json")
	before := mint(t, s, s.env["TOOLGATE_SIGNING_KEYS"])  // k2, the active key
	retired := mint(t, s, "k1="+strings.Repeat("ef", 32)) // k1, also listed
	s.env["TOOLGATE_KEYS_FILE"] = kf
	s.env["TOOLGATE_SIGNING_ROTATE_EVERY"], s.env["TOOLGATE_SIGNING_OVERLAP"] = fastAgent.RotateEvery.String(), fastAgent.Overlap.String()
	s.env["TOOLGATE_LOG_LEVEL"] = "info"
	if _, err := mintWith(t, s); err == nil || !strings.Contains(err.Error(), "has no agent ring yet") {
		t.Fatalf("mint before the ring exists: %v", err)
	}
	r := s.start(t)
	logs := r.logs.String()
	for _, want := range []string{
		`"msg":"starting the ring from TOOLGATE_SIGNING_KEYS","keys_file":"` + kf + `","ring":"agent","keys":2`,
		`"msg":"agent tokens on a key ring","keys_file":"` + kf + `","ring":"agent","signing_rotate_every":"1s","signing_overlap":"4s"`,
		`"msg":"key rotation: signing_overlap 4s is shorter than the agents config's longest token lifetime 1h0m0s`,
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("no %s in %s", want, logs)
		}
	}
	for name, tok := range map[string]string{"active signing key": before, "listed signing key": retired} {
		if res := readFile(t, r, tok); !ok(res) {
			t.Fatalf("%s: %v", name, res)
		}
	}
	// The file holds the ring, k2 current; mint signs with it.
	f, err := keys.OpenFile(kf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ring := f.Set().Ring(keys.RingAgent); ring == nil || ring.Alg() != keys.HS256 {
		t.Fatalf("agent ring %v", ring)
	}
	tok, err := mintWith(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if kid := kidOf(t, tok); kid != "k2" && !strings.Contains(r.logs.String(), `"msg":"key ring rotated"`) {
		t.Fatalf("minted with %s before any rotation", kid)
	}

	// Under load, tokens minted from the file while the ring rotates all
	// verify.
	var stop atomic.Bool
	var calls, failures atomic.Int64
	var mu sync.Mutex
	var failed []string
	var wg sync.WaitGroup
	toks := make(chan string, 64)
	toks <- tok
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cur := <-toks
			for !stop.Load() {
				select {
				case cur = <-toks:
				default:
				}
				calls.Add(1)
				if res := readFile(t, r, cur); !ok(res) {
					failures.Add(1)
					mu.Lock()
					failed = append(failed, kidOf(t, cur))
					mu.Unlock()
				}
			}
		}()
	}
	kids := map[string]bool{}
	deadline := time.Now().Add(3500 * time.Millisecond)
	for time.Now().Before(deadline) {
		tk, err := mintWith(t, s)
		if err != nil {
			t.Fatal(err)
		}
		kids[kidOf(t, tk)] = true
		for range 4 {
			select {
			case toks <- tk:
			default:
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	if failures.Load() > 0 {
		t.Fatalf("%d of %d calls failed across rotations (keys %v)", failures.Load(), calls.Load(), failed)
	}
	if len(kids) < 2 {
		t.Fatalf("minted with %d keys in 3.5s of 1s rotations: %v", len(kids), kids)
	}
	if !strings.Contains(r.logs.String(), `"msg":"key ring rotated","keys_file":"`+kf+`","ring":"agent","signing_kid":`) {
		t.Fatalf("no rotation logged: %s", r.logs.String())
	}
	t.Logf("%d calls, no failures, tokens from %d keys", calls.Load(), len(kids))

	// The seeded keys retired over 4 s after the start: their tokens are
	// refused once that ends, as a rotated-out key's are.
	within(t, "seeded keys retire", func() bool {
		return readFile(t, r, before)["error"] != nil && readFile(t, r, retired)["error"] != nil
	})
	r.stop(t)

	// On restart the file's ring is used, and the signing keys are
	// ignored with a warning.
	r = s.start(t)
	if !strings.Contains(r.logs.String(), `"msg":"the keys file already holds this ring; TOOLGATE_SIGNING_KEYS is ignored and can be removed"`) {
		t.Fatalf("restart log: %s", r.logs.String())
	}
	tk, err := mintWith(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if res := readFile(t, r, tk); !ok(res) {
		t.Fatalf("token after restart: %v", res)
	}
	r.stop(t)
}

// A keys file needs the agents config's tokens section, and a file whose
// agent ring is not HS256 stops the gateway and token mint.
func TestKeysFileStartErrors(t *testing.T) {
	s := newSetup(t)
	s.env["TOOLGATE_KEYS_FILE"] = filepath.Join(s.dir, "keys.json")
	delete(s.env, "TOOLGATE_SIGNING_KEYS")
	s.env["TOOLGATE_CONFIG"] = writeConfigWithoutTokens(t, s)
	var logs bytes.Buffer
	if code := cli(context.Background(), nil, s.getenv, nil, &logs, &logs, nil); code != 1 ||
		!strings.Contains(logs.String(), "a keys file is set but the config has no tokens section") {
		t.Fatalf("no tokens section: %d %s", code, logs.String())
	}
	if _, err := os.Stat(s.env["TOOLGATE_KEYS_FILE"]); err == nil {
		t.Fatal("the keys file was written for a gateway that did not start")
	}

	s = newSetup(t)
	wrong := filepath.Join(s.dir, "wrong.json")
	set := keys.NewSet()
	ring, _ := keys.NewRing(keys.ES256, keys.Policy{}, time.Now())
	set.Add(keys.RingAgent, ring)
	if err := set.Save(wrong); err != nil {
		t.Fatal(err)
	}
	s.env["TOOLGATE_KEYS_FILE"] = wrong
	logs.Reset()
	if code := cli(context.Background(), nil, s.getenv, nil, &logs, &logs, nil); code != 1 ||
		!strings.Contains(logs.String(), "ring agent holds ES256 keys, want HS256") {
		t.Fatalf("wrong alg: %d %s", code, logs.String())
	}
	if _, err := mintWith(t, s); err == nil || !strings.Contains(err.Error(), "ring agent holds ES256 keys, want HS256") {
		t.Fatalf("mint from a wrong ring: %v", err)
	}
	if _, err := mintWith(t, s, "TOOLGATE_KEYS_FILE", filepath.Join(s.dir, "garbage")); err == nil {
		t.Fatal("mint from a missing file directory succeeded")
	}
	os.WriteFile(filepath.Join(s.dir, "garbage"), []byte("{"), 0o600)
	if _, err := mintWith(t, s, "TOOLGATE_KEYS_FILE", filepath.Join(s.dir, "garbage")); err == nil {
		t.Fatal("mint from an unreadable file succeeded")
	}
	if _, err := mintWith(t, s, "TOOLGATE_KEYS_FILE", "", "TOOLGATE_SIGNING_KEYS", ""); err == nil ||
		!strings.Contains(err.Error(), "TOOLGATE_SIGNING_KEYS or TOOLGATE_KEYS_FILE is required to mint tokens") {
		t.Fatalf("mint with no keys: %v", err)
	}
	if _, err := mintWith(t, s, "TOOLGATE_KEYS_FILE", "", "TOOLGATE_SIGNING_KEYS", "k=zz"); err == nil {
		t.Fatal("mint with a bad key succeeded")
	}
}

// From a platform file: keys_file puts agent tokens on the ring, an agents
// config reload keeps them on it, and a signing_keys change applies on
// restart only, since the ring now holds the keys.
func TestKeysFileFromSection(t *testing.T) {
	f := newFileSetup(t)
	kf := filepath.Join(f.dir, "keys.json")
	before := mint(t, f.setup, f.env["TOOLGATE_SIGNING_KEYS"])
	f.writeDoc(t, map[string]any{"keys_file": kf})
	r := f.start(t)
	if !strings.Contains(r.logs.String(), `"msg":"starting the ring from signing_keys"`) {
		t.Fatalf("start-up log: %s", r.logs.String())
	}
	if res := readFile(t, r, before); !ok(res) {
		t.Fatalf("seeded key: %v", res)
	}
	tok, err := mintWith(t, f.setup, "TOOLGATE_KEYS_FILE", kf)
	if err != nil {
		t.Fatal(err)
	}
	if res := readFile(t, r, tok); !ok(res) {
		t.Fatalf("ring token: %v", res)
	}

	// carol is added: the reloaded authenticator is on the same ring.
	f.write(t, f.agents, f.agentsDoc(t, true, 0))
	within(t, "new agent", func() bool { return ok(readFile(t, r, carolKey)) })
	if res := readFile(t, r, tok); !ok(res) {
		t.Fatalf("ring token after an agents reload: %v", res)
	}

	// New signing keys do not replace the ring.
	f.write(t, f.keysFile, "k3="+rotatedKey)
	within(t, "signing_keys on restart", func() bool {
		return strings.Contains(r.logs.String(), `"msg":"configuration changes apply when authz mcp restarts","members":["signing_keys"]`)
	})
	if res := readFile(t, r, tok); !ok(res) {
		t.Fatalf("ring token after a signing_keys change: %v", res)
	}
	if res := readFile(t, r, mint(t, f.setup, "k3="+rotatedKey)); res["error"] == nil {
		t.Fatal("a token from the new signing keys verified; the ring should hold the keys")
	}
	r.stop(t)
}

// Parts of one process naming the same keys file share its agent ring.
func TestKeysFileSharedInProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	h := part.Host{Keys: new(keys.Files)}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := config{keysFile: path, signingPol: DefaultSigningPolicy}
	a, err := openFileKeys(h, c, time.Now(), log, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := openFileKeys(h, c, time.Now(), log, true)
	if err != nil || a.ring != b.ring || a.file != b.file {
		t.Fatalf("not shared: %v", err)
	}
	// Under another policy, the ring already in use is refused.
	c.signingPol = keys.Policy{RotateEvery: time.Hour, Overlap: 2 * time.Hour}
	if _, err := openFileKeys(h, c, time.Now(), log, false); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("policy conflict: %v", err)
	}
}

func TestSigningKeyList(t *testing.T) {
	now := time.Now()
	k := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	ks, err := signingKeyList(map[string][]byte{"b": k(1), "a": k(2), "z": k(3)}, "z", now)
	if err != nil || len(ks) != 3 || ks[0].ID() != "z" || ks[1].ID() != "a" || ks[2].ID() != "b" {
		t.Fatalf("%v %v", ks, err)
	}
	if ks, err := signingKeyList(nil, "", now); ks != nil || err != nil {
		t.Fatalf("empty: %v %v", ks, err)
	}
	if _, err := signingKeyList(map[string][]byte{"a": k(1)[:8]}, "a", now); err == nil || !strings.HasPrefix(err.Error(), "signing key a: ") {
		t.Fatalf("short key: %v", err)
	}
	ring, err := configuredRing(config{keys: map[string][]byte{"a": k(1), "b": k(2)}, activeKey: "b"}, now)
	if err != nil || ring.Current().ID() != "b" || ring.Lookup("a", now.Add(1000*time.Hour)) == nil || ring.Due(now.Add(1000*time.Hour)) {
		t.Fatalf("configured ring: %v", err)
	}
	if hex.EncodeToString(ring.Current().Secret()) != hex.EncodeToString(k(2)) {
		t.Fatal("wrong secret")
	}
	if w := keyPolicyWarnings(keys.Policy{}, time.Hour); w != nil {
		t.Fatalf("never rotating: %v", w)
	}
	if w := keyPolicyWarnings(DefaultSigningPolicy, 24*time.Hour); w != nil {
		t.Fatalf("default: %v", w)
	}
}
