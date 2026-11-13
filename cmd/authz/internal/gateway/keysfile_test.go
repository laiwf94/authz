package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/cmd/authz/internal/part"
	"github.com/laiwf94/authz/internal/authn/policy"
	"github.com/laiwf94/authz/internal/authn/session"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/jose"
	"github.com/laiwf94/authz/internal/platform/keys"
	"github.com/laiwf94/authz/internal/platform/seal"
)

// fast rotates both rings every second and keeps retired keys for 4 s.
var fast = keys.Policy{RotateEvery: time.Second, Overlap: 4 * time.Second}

func TestKeysFileVariables(t *testing.T) {
	base := map[string]string{"WICKET_CONFIG": "c", "WICKET_KEYS_FILE": "/k.json"}
	s, err := loadSettings(env(base))
	if err != nil {
		t.Fatalf("a keys file makes WICKET_COOKIE_KEYS optional: %v", err)
	}
	if s.keysFile != "/k.json" || s.cookiePol != DefaultCookiePolicy || s.signingPol != DefaultSigningPolicy || s.cookieKeys != nil {
		t.Fatalf("settings %+v", s)
	}
	set := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	s, err = loadSettings(env(set("WICKET_COOKIE_ROTATE_EVERY", "1h", "WICKET_COOKIE_OVERLAP", "12h",
		"WICKET_SIGNING_ROTATE_EVERY", "0s", "WICKET_SIGNING_OVERLAP", "0s", "WICKET_COOKIE_KEYS", cookieKey)))
	if err != nil || s.cookiePol != (keys.Policy{RotateEvery: time.Hour, Overlap: 12 * time.Hour}) || s.signingPol != (keys.Policy{}) ||
		len(s.cookieKeys) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	for _, c := range []struct{ kv []string }{
		{[]string{"WICKET_COOKIE_ROTATE_EVERY", "daily"}},
		{[]string{"WICKET_SIGNING_OVERLAP", "-1h"}},
		{[]string{"WICKET_COOKIE_OVERLAP", "0s"}},
		{[]string{"WICKET_SIGNING_ROTATE_EVERY", "1ms"}},
	} {
		if _, err := loadSettings(env(set(c.kv...))); err == nil {
			t.Errorf("%v accepted", c.kv)
		}
	}
	if _, err := loadSettings(env(map[string]string{"WICKET_CONFIG": "c"})); err == nil ||
		err.Error() != "WICKET_COOKIE_KEYS is required (run: authz gateway genkey)" {
		t.Errorf("no keys at all: %v", err)
	}
}

// The section's keys members start the gateway with the settings the same
// WICKET_ variables give.
func TestKeysFileSectionMatchesVariables(t *testing.T) {
	vars := map[string]string{"WICKET_CONFIG": "/c.json", "WICKET_KEYS_FILE": "/var/lib/authz/keys.json",
		"WICKET_COOKIE_ROTATE_EVERY": "12h", "WICKET_COOKIE_OVERLAP": "36h",
		"WICKET_SIGNING_ROTATE_EVERY": "6h", "WICKET_SIGNING_OVERLAP": "1h"}
	want, err := loadSettings(env(vars))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	kf := filepath.Join(dir, "keys.json")
	doc := `{"version": 1, "gateway": {"keys_file": "` + kf + `", "cookie_rotate_every": "12h", "cookie_overlap": "36h",
	  "signing_rotate_every": "6h", "signing_overlap": "1h", ` + wicketDoc + `}}`
	r := Schema(env(map[string]string{"CORP_SECRET": "s"})).Check([]byte(doc), nil)
	if len(r.Problems) != 0 {
		t.Fatal(r.Problems)
	}
	got, err := sectionSettings(pcfg.Get[Settings](r.Config, SectionName))
	if err != nil {
		t.Fatal(err)
	}
	want.configPath, want.keysFile, want.loginRate = "", kf, 30
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("section:\n%+v\nvariables:\n%+v", got, want)
	}
}

func TestKeysFileSectionChecks(t *testing.T) {
	dir := t.TempDir()
	wrongAlg := filepath.Join(dir, "wrong.json")
	set := keys.NewSet()
	r, _ := keys.NewRing(keys.HS256, keys.Policy{}, time.Now())
	set.Add(keys.RingSession, r)
	if err := set.Save(wrongAlg); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage.json")
	os.WriteFile(garbage, []byte("{"), 0o600)
	sc := Schema(env(map[string]string{"CORP_SECRET": "s"}))
	for name, c := range map[string]struct {
		members, path, msg string
		warn               bool
	}{
		"no keys":        {`"addr": ":4180"`, "$.gateway.cookie_keys", "is required (run: authz gateway genkey), or keys_file", false},
		"wrong alg":      {`"keys_file": "` + wrongAlg + `"`, "$.gateway.keys_file", "ring session holds HS256 keys, want A256GCM", false},
		"garbage":        {`"keys_file": "` + garbage + `"`, "$.gateway.keys_file", garbage, false},
		"no directory":   {`"keys_file": "` + filepath.Join(dir, "none", "k.json") + `"`, "$.gateway.keys_file", "can't be created", false},
		"no overlap":     {`"keys_file": "k.json", "cookie_overlap": "0s"`, "$.gateway.cookie_overlap", "needs an overlap", false},
		"long overlap":   {`"keys_file": "k.json", "signing_rotate_every": "1h", "signing_overlap": "20h"`, "$.gateway.signing_overlap", "longer than 15 rotation periods", false},
		"short overlap":  {`"keys_file": "k.json", "cookie_overlap": "4h"`, "$.gateway.cookie_overlap", "shorter than the session's absolute timeout 8h0m0s", true},
		"longer session": {`"keys_file": "k.json", "session"`, "$.gateway.cookie_overlap", "absolute timeout 72h0m0s", true},
		"token ttl":      {`"keys_file": "k.json", "signing_rotate_every": "10s", "signing_overlap": "30s"`, "$.gateway.signing_overlap", "shorter than upstream_token_ttl 1m0s", true},
		"fast signing":   {`"keys_file": "k.json", "signing_rotate_every": "1m", "signing_overlap": "2m"`, "$.gateway.signing_rotate_every", "may cache the JWKS", true},
	} {
		members := c.members
		wd := wicketDoc
		if strings.Contains(members, `"session"`) {
			wd = strings.Replace(wicketDoc, `"absolute_timeout": "8h"`, `"absolute_timeout": "72h"`, 1)
			members = `"keys_file": "k.json"`
		}
		doc := `{"version": 1, "gateway": {` + members + `, ` + wd + `}}`
		res := sc.Check([]byte(strings.ReplaceAll(doc, `"k.json"`, `"`+filepath.Join(dir, "k.json")+`"`)), nil)
		found := false
		for _, p := range res.Problems {
			if p.Path == c.path && strings.Contains(p.Message, c.msg) && (p.Severity == pcfg.SeverityWarning) == c.warn {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want %s %q (warning %v), got %v", name, c.path, c.msg, c.warn, res.Problems)
		}
	}
	// With a keys file, neither key list is needed, and the defaults pass.
	doc := `{"version": 1, "gateway": {"keys_file": "` + filepath.Join(dir, "k.json") + `", ` + wicketDoc + `}}`
	if res := sc.Check([]byte(doc), nil); len(res.Problems) != 0 {
		t.Errorf("defaults: %v", res.Problems)
	}
}

// keysGateway is "authz gateway" from WICKET_ variables with a keys file
// whose rings rotate every second.
type keysGateway struct {
	t        *testing.T
	dir      string
	keysFile string
	public   string
	log      *syncBuf
	secrets  []string // signed-in sessions in the session file
	cancel   context.CancelFunc
	done     chan error
}

func newKeysGateway(t *testing.T, sessions int) *keysGateway {
	dir := t.TempDir()
	g := &keysGateway{t: t, dir: dir, keysFile: filepath.Join(dir, "keys.json")}
	st, err := session.Open(session.Options{Path: filepath.Join(dir, "sessions.log")})
	if err != nil {
		t.Fatal(err)
	}
	for i := range sessions {
		sec, _, err := st.Create(policy.Identity{Provider: "corp", Subject: fmt.Sprintf("user%d", i)}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		g.secrets = append(g.secrets, sec)
	}
	st.Close()
	return g
}

func (g *keysGateway) vars(extra map[string]string) map[string]string {
	m := map[string]string{"WICKET_CONFIG": writeConfig(g.t, g.dir), "CORP_SECRET": "s",
		"WICKET_ADDR": "127.0.0.1:0", "WICKET_ADMIN_ADDR": "127.0.0.1:0",
		"WICKET_SESSION_FILE": filepath.Join(g.dir, "sessions.log"), "WICKET_KEYS_FILE": g.keysFile,
		"WICKET_COOKIE_ROTATE_EVERY": fast.RotateEvery.String(), "WICKET_COOKIE_OVERLAP": fast.Overlap.String(),
		"WICKET_SIGNING_ROTATE_EVERY": fast.RotateEvery.String(), "WICKET_SIGNING_OVERLAP": fast.Overlap.String()}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func (g *keysGateway) start(h part.Host, vars map[string]string) {
	g.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel, g.done, g.log = cancel, make(chan error, 1), &syncBuf{}
	addrs := make(chan [2]string, 1)
	go func() {
		g.done <- serveIn(ctx, h, env(vars), "", g.log, make(chan os.Signal), func(p, a string) { addrs <- [2]string{p, a} }, nil)
	}()
	select {
	case a := <-addrs:
		g.public = a[0]
	case err := <-g.done:
		g.t.Fatal(err)
	}
}

func (g *keysGateway) stop() {
	g.t.Helper()
	g.cancel()
	if err := <-g.done; err != nil {
		g.t.Fatal(err)
	}
}

// fileCookie seals secret with the session ring's current key as the
// keys file holds it now.
func (g *keysGateway) fileCookie(secret string) string {
	g.t.Helper()
	set, err := keys.Load(g.keysFile)
	if err != nil {
		g.t.Fatal(err)
	}
	kr, err := seal.FromRing(set.Ring(keys.RingSession), nil)
	if err != nil {
		g.t.Fatal(err)
	}
	return "__Host-wicket=" + kr.Seal("session", []byte(secret))
}

// auth returns the status and the upstream token for a request to the app.
func (g *keysGateway) auth(c *http.Client, cookie string) (int, string, error) {
	req, _ := http.NewRequest("GET", "http://"+g.public+"/auth", nil)
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Uri", "/")
	req.Header.Set("Cookie", cookie)
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("X-Auth-Token"), nil
}

func (g *keysGateway) jwks(c *http.Client) (*jose.KeySet, []string, error) {
	resp, err := c.Get("http://" + g.public + "/.well-known/jwks.json")
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	ks, err := jose.ParseKeySet(b)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", err, b)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	json.Unmarshal(b, &doc)
	var kids []string
	for _, k := range doc.Keys {
		kids = append(kids, k.Kid)
	}
	return ks, kids, nil
}

func tokenKid(t testing.TB, tok string) string {
	t.Helper()
	pt, err := jose.Parse(tok)
	if err != nil {
		t.Fatalf("upstream token %q: %v", tok, err)
	}
	return pt.Header.Kid
}

func verifies(ks *jose.KeySet, tok string) bool {
	pt, err := jose.Parse(tok)
	if err != nil {
		return false
	}
	for _, k := range ks.Keys {
		if k.ID == pt.Header.Kid {
			return pt.Verify(k, []string{"ES256"}) == nil
		}
	}
	return false
}

// The first start with a keys file takes the key lists into the new rings,
// so a cookie sealed with WICKET_COOKIE_KEYS and the published signing key
// keep working; the rings then rotate every second, the JWKS follows, the
// old cookie stops opening once its overlap ends, and a restart keeps the
// rings.
func TestKeysFileGateway(t *testing.T) {
	g := newKeysGateway(t, 4)
	var pemOut strings.Builder
	subcommand("gensigningkey", &pemOut)
	signPEM := filepath.Join(g.dir, "sign.pem")
	os.WriteFile(signPEM, []byte(pemOut.String()), 0o600)
	oldSigner, err := loadSigners([]string{signPEM})
	if err != nil {
		t.Fatal(err)
	}
	vars := g.vars(map[string]string{"WICKET_COOKIE_KEYS": cookieKey, "WICKET_SIGNING_KEYS": signPEM})
	g.start(part.Host{}, vars)
	if !strings.Contains(g.log.String(), `"msg":"starting the ring from cookie_keys"`) ||
		!strings.Contains(g.log.String(), `"msg":"starting the ring from signing_keys"`) {
		t.Fatalf("seeding not logged:\n%s", g.log.String())
	}
	c := &http.Client{Timeout: 5 * time.Second}
	listCookie := cookie(t, cookieKey, g.secrets[0])
	code, tok, err := g.auth(c, listCookie)
	if err != nil || code != 200 {
		t.Fatalf("a cookie sealed with WICKET_COOKIE_KEYS: %d %v\n%s", code, err, g.log.String())
	}
	if kid := tokenKid(t, tok); kid != oldSigner[0].KeyID() {
		t.Fatalf("first token signed by %s, want the WICKET_SIGNING_KEYS key %s", kid, oldSigner[0].KeyID())
	}
	ks, kids, err := g.jwks(c)
	if err != nil || len(kids) != 2 || kids[0] != oldSigner[0].KeyID() || !verifies(ks, tok) {
		t.Fatalf("JWKS %v %v: want the signing key and the next one", kids, err)
	}
	next := kids[1]

	// After a rotation the next key signs, the old key stays published, and
	// the cookie sealed with the old list still opens.
	waitFor(t, func() bool { return strings.Contains(g.log.String(), `"ring":"upstream","signing_kid"`) })
	code, tok2, err := g.auth(c, g.fileCookie(g.secrets[1]))
	if err != nil || code != 200 {
		t.Fatalf("a cookie sealed with the file's current key: %d %v", code, err)
	}
	if kid := tokenKid(t, tok2); kid == oldSigner[0].KeyID() {
		t.Fatal("still signing with the retired key after a rotation")
	} else if !strings.Contains(g.log.String(), `"signing_kid":"`+next+`"`) && kid != next {
		t.Fatalf("token signed by %s; the published next key was %s", kid, next)
	}
	ks, kids, _ = g.jwks(c)
	if !verifies(ks, tok) || !verifies(ks, tok2) {
		t.Fatalf("JWKS %v lost a key still inside its overlap", kids)
	}
	if code, _, _ := g.auth(c, listCookie); code != 200 {
		t.Fatalf("the WICKET_COOKIE_KEYS cookie inside its overlap: %d", code)
	}
	// Once the overlap ends, the seeded cookie key and signing key are gone.
	start := time.Now()
	waitFor(t, func() bool { code, _, _ := g.auth(c, listCookie); return code == 401 })
	if d := time.Since(start); d > fast.Overlap+2*time.Second {
		t.Fatalf("the retired cookie key opened cookies for %v", d)
	}
	waitFor(t, func() bool { ks, _, _ := g.jwks(c); return !verifies(ks, tok) })

	// A restart keeps the rings: a cookie sealed from the file opens, and
	// the lists, still set, are ignored with a warning.
	fresh := g.fileCookie(g.secrets[2])
	g.stop()
	g.start(part.Host{}, vars)
	if code, _, _ := g.auth(c, fresh); code != 200 {
		t.Fatalf("a cookie from before the restart: %d", code)
	}
	if n := strings.Count(g.log.String(), "the keys file already holds this ring"); n != 2 {
		t.Fatalf("%d warnings about ignored key lists, want 2:\n%s", n, g.log.String())
	}
	if code, _, _ := g.auth(c, listCookie); code != 401 {
		t.Fatalf("the ignored list reopened the cookie: %d", code)
	}
	g.stop()
	fi, err := os.Stat(g.keysFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("keys file: %v %v", fi, err)
	}
}

// Logins and upstream token checks under load while both rings rotate
// every second: every cookie is sealed from the file as it stands, every
// token is checked against a JWKS fetched at most a rotation period
// earlier, and nothing fails.
func TestKeysFileGatewayUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("rotates for several seconds")
	}
	const clients = 8
	g := newKeysGateway(t, clients)
	g.start(part.Host{}, g.vars(nil))
	defer g.stop()
	var (
		requests, failures, crossed atomic.Int64
		mu                          sync.Mutex
		failed                      []string
		kidsSeen                    = map[string]bool{}
	)
	fail := func(f string, a ...any) {
		failures.Add(1)
		mu.Lock()
		if len(failed) < 10 {
			failed = append(failed, fmt.Sprintf(f, a...))
		}
		mu.Unlock()
	}
	deadline := time.Now().Add(6 * time.Second)
	var wg sync.WaitGroup
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Timeout: 5 * time.Second}
			var ks *jose.KeySet
			var fetched time.Time
			cookie, sealed := "", time.Time{}
			for time.Now().Before(deadline) {
				if time.Since(fetched) > fast.RotateEvery {
					var err error
					if ks, _, err = g.jwks(c); err != nil {
						fail("jwks: %v", err)
						return
					}
					fetched = time.Now()
				}
				// A cookie is reused for up to two rotation periods, so many
				// requests open it under a retired key.
				if time.Since(sealed) > 2*fast.RotateEvery {
					cookie, sealed = g.fileCookie(g.secrets[i]), time.Now()
				}
				code, tok, err := g.auth(c, cookie)
				requests.Add(1)
				switch {
				case err != nil:
					fail("auth: %v", err)
				case code != 200:
					fail("auth: status %d", code)
				case !verifies(ks, tok):
					fail("token by %s not in a JWKS fetched %v earlier", tokenKid(t, tok), time.Since(fetched))
				default:
					kid := tokenKid(t, tok)
					mu.Lock()
					kidsSeen[kid] = true
					mu.Unlock()
					if time.Since(sealed) > fast.RotateEvery {
						crossed.Add(1)
					}
				}
			}
		}()
	}
	wg.Wait()
	t.Logf("%d requests, %d with a cookie older than a rotation, %d signing keys, %d failures",
		requests.Load(), crossed.Load(), len(kidsSeen), failures.Load())
	if failures.Load() > 0 {
		t.Fatalf("%d failures: %v\n%s", failures.Load(), failed, g.log.String())
	}
	if len(kidsSeen) < 3 || crossed.Load() == 0 {
		t.Fatalf("too few rotations seen: %d signing keys, %d crossed", len(kidsSeen), crossed.Load())
	}
}

// Serve and the gateway naming one keys file in one process share it:
// both rings join the file serve's consistency ring is in.
func TestKeysFileShared(t *testing.T) {
	g := newKeysGateway(t, 1)
	files := new(keys.Files)
	kf, err := files.Open(g.keysFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kf.Ensure(keys.Spec{Name: keys.RingConsistency, Alg: keys.HS256}); err != nil {
		t.Fatal(err)
	}
	g.start(part.Host{Keys: files}, g.vars(nil))
	if got := kf.Set().Names(); !reflect.DeepEqual(got, []string{keys.RingConsistency, keys.RingSession, keys.RingUpstream}) {
		t.Fatalf("rings %v", got)
	}
	c := &http.Client{Timeout: 5 * time.Second}
	if code, _, _ := g.auth(c, g.fileCookie(g.secrets[0])); code != 200 {
		t.Fatalf("auth: %d", code)
	}
	g.stop()
}

// A keys file the gateway can't use stops it at start-up.
func TestKeysFileStartErrors(t *testing.T) {
	g := newKeysGateway(t, 0)
	wrong := keys.NewSet()
	r, _ := keys.NewRing(keys.EdDSA, keys.Policy{}, time.Now())
	wrong.Add(keys.RingUpstream, r)
	wrong.Save(g.keysFile)
	err := serveIn(context.Background(), part.Host{}, env(g.vars(nil)), "", io.Discard, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "ring upstream holds EdDSA keys, want ES256") {
		t.Errorf("wrong alg: %v", err)
	}
	os.WriteFile(g.keysFile, []byte("{"), 0o600)
	if err := serveIn(context.Background(), part.Host{}, env(g.vars(nil)), "", io.Discard, nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "keys file") {
		t.Errorf("broken file: %v", err)
	}
	os.Remove(g.keysFile)
	bad := filepath.Join(g.dir, "bad.pem")
	os.WriteFile(bad, []byte("not pem"), 0o600)
	if err := serveIn(context.Background(), part.Host{}, env(g.vars(map[string]string{"WICKET_SIGNING_KEYS": bad})), "", io.Discard, nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("bad seed: %v", err)
	}
	if _, err := os.Stat(g.keysFile); err == nil {
		t.Error("a refused start wrote the keys file")
	}
}

// Under a platform file, a keys file's rings and cookie_keys changes wait
// for a restart.
func TestKeysFileRestartOnly(t *testing.T) {
	a := settings{keysFile: "/k", cookiePol: DefaultCookiePolicy, signingPol: DefaultSigningPolicy, cookieKeys: [][]byte{[]byte("a")}}
	b := a
	b.keysFile, b.cookiePol, b.signingPol, b.cookieKeys = "/other", fast, fast, [][]byte{[]byte("b")}
	if got := restartOnly(a, b); !reflect.DeepEqual(got, []string{"cookie_keys", "keys_file", "cookie_rotation", "signing_rotation"}) {
		t.Fatalf("restart only: %v", got)
	}
	a.keysFile = ""
	b.keysFile = ""
	if got := restartOnly(a, b); !reflect.DeepEqual(got, []string{"cookie_rotation", "signing_rotation"}) {
		t.Fatalf("without a keys file cookie_keys reloads: %v", got)
	}
}
