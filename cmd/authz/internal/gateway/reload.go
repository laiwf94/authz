package gateway

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laiwf94/authz/internal/authn/check"
	"github.com/laiwf94/authz/internal/authn/config"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/httpserver"
	"github.com/laiwf94/authz/internal/platform/seal"
)

// ConfigEnv names the platform configuration file when -config is not
// given.
const ConfigEnv = "AUTHZ_CONFIG"

// OtherSections are the sections of the platform file that belong to the
// other long-running subcommands. "authz gateway -config" reads past them,
// so one file can configure every subcommand and a problem in another's
// section does not stop this one.
var OtherSections = []string{"serve", "mcp"}

// Schema is what "authz gateway -config" reads: its own section, checked
// offline with getenv resolving client_secret_env, and the others skipped.
func Schema(getenv func(string) string) *pcfg.Schema {
	secs := []pcfg.Section{Section(SectionOptions{Check: check.Options{Getenv: getenv}})}
	for _, name := range OtherSections {
		secs = append(secs, pcfg.Skip(name))
	}
	return pcfg.MustSchema(secs...)
}

// sectionSettings is the gateway's start-up configuration from a checked
// section, the same one loadSettings builds from the WICKET_ variables. It
// has no configPath: the wicket members are in the section.
func sectionSettings(s *Settings) (settings, error) {
	st := settings{addr: s.Addr, adminAddr: s.AdminAddr, adminToken: s.AdminToken.Value(), sessionFile: s.SessionFile,
		auditLog: s.AuditLog, signingKeys: slices.Clone(s.SigningKeys), loginRate: s.LoginRate}
	var err error
	if st.cookieKeys, err = cookieKeys(s.CookieKeys.Value()); err != nil {
		return st, err
	}
	for i, p := range s.TrustedProxies {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(p))
		if err != nil {
			return st, fmt.Errorf("$.gateway.trusted_proxies[%d]: %q is not a CIDR", i, p)
		}
		st.trusted = append(st.trusted, pfx)
	}
	if err := st.logLevel.UnmarshalText([]byte(s.LogLevel)); err != nil {
		return st, fmt.Errorf("$.gateway.log_level: %v", err)
	}
	st.http = httpserver.Options{TLS: s.tlsFiles(), DrainDelay: time.Duration(s.DrainDelay), DrainTimeout: time.Duration(s.DrainTimeout)}
	return st, nil
}

// cookieKeys reads the cookie_keys list: comma-separated keys of 64 hex
// characters, the first sealing.
func cookieKeys(v string) ([][]byte, error) {
	var out [][]byte
	for i, k := range strings.Split(v, ",") {
		if k = strings.TrimSpace(k); k == "" {
			continue
		}
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != seal.KeySize {
			return nil, fmt.Errorf("$.gateway.cookie_keys: entry %d is not 64 hex characters (run: authz gateway genkey)", i+1)
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		return nil, errors.New("$.gateway.cookie_keys holds no key (run: authz gateway genkey)")
	}
	if _, err := seal.New(out); err != nil {
		return nil, fmt.Errorf("$.gateway.cookie_keys: %s", strings.TrimPrefix(err.Error(), "seal: "))
	}
	return out, nil
}

// watchFile loads the gateway section of the platform configuration file
// at path and watches it, and the secret files it names, for changes that
// rl applies once the gateway runs.
func watchFile(path string, getenv func(string) string, rl *reloader) (*pcfg.Watcher, settings, error) {
	sc := Schema(getenv)
	w, err := pcfg.NewWatcher(sc, path, pcfg.WatchOptions{
		Environ:  sc.Environ(getenv),
		Validate: validateFile,
		OnReload: rl.reload,
		OnError:  rl.refused,
	})
	if err != nil {
		return nil, settings{}, err
	}
	st, err := sectionSettings(pcfg.Get[Settings](w.Current(), SectionName))
	return w, st, err
}

// validateFile refuses a document with no gateway section: "authz gateway"
// would have nothing to run from.
func validateFile(c *pcfg.Config) error {
	s := pcfg.Get[Settings](c, SectionName)
	if s == nil {
		return errors.New(`$.gateway: the file has no gateway section (nor any AUTHZ_GATEWAY_ variable)`)
	}
	_, err := sectionSettings(s)
	return err
}

// wicketVars lists the WICKET_ variables that are set, which a
// configuration file replaces.
func wicketVars(getenv func(string) string) []string {
	var out []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "WICKET_") && getenv(k) != "" {
			out = append(out, k)
		}
	}
	for _, k := range []string{"WICKET_CONFIG", "WICKET_COOKIE_KEYS", "WICKET_ADDR", "WICKET_ADMIN_ADDR", "WICKET_ADMIN_TOKEN",
		"WICKET_SESSION_FILE", "WICKET_SIGNING_KEYS", "WICKET_TRUSTED_PROXIES", "WICKET_LOGIN_RATE", "WICKET_LOG_LEVEL",
		"WICKET_AUDIT_LOG", "WICKET_TLS_CERT", "WICKET_TLS_KEY", "WICKET_TLS_CLIENT_CA", "WICKET_DRAIN_DELAY", "WICKET_DRAIN_TIMEOUT"} {
		if getenv(k) != "" && !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// reloader applies a changed gateway section to the running gateway. The
// cookie keys and the log level change at once, in the watcher's poll;
// the providers, apps and the rest of the wicket members are rebuilt by
// the serve loop, which changed wakes. The members that cannot change
// while the gateway runs are logged as applying on restart.
type reloader struct {
	level   *slog.LevelVar
	changed chan struct{} // buffered 1: the serve loop rebuilds the server's runtime

	// loaded is the configuration the server's runtime was last built
	// from, so a change the server already picked up (a reload that polled
	// the file itself) is not built twice.
	loaded atomic.Pointer[pcfg.Config]
	// polling is set while the server's Load looks at the files itself: a
	// change that poll finds is built by that Load, so the serve loop is not
	// woken for it.
	polling atomic.Bool

	mu      sync.Mutex
	log     *slog.Logger
	keys    *seal.Keyring
	started settings // what the process started with
	applied settings // the cookie keys and level in use
}

func newReloader(level *slog.LevelVar) *reloader {
	return &reloader{level: level, changed: make(chan struct{}, 1)}
}

// start hands the reloader the running gateway's log and cookie key ring.
// The watcher is started after it, so reload and refused always have them.
func (r *reloader) start(log *slog.Logger, keys *seal.Keyring, st settings) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log, r.keys, r.started, r.applied = log, keys, st, st
}

// config returns the wicket configuration the watcher holds now and notes
// it as the one the server is built from.
func (r *reloader) config(w *pcfg.Watcher, getenv func(string) string) (*config.Config, error) {
	cur := w.Current()
	cfg, err := config.Parse(pcfg.Get[Settings](cur, SectionName).File(), getenv)
	if err != nil {
		return nil, fmt.Errorf("$.gateway: %w", err)
	}
	r.loaded.Store(cur)
	return cfg, nil
}

// poll looks at the watcher's files at once, for a reload the server
// asked for. Files the watcher's own poll already refused are unchanged
// since, but the reload still fails with the reason (#238).
func (r *reloader) poll(w *pcfg.Watcher) error {
	r.polling.Store(true)
	defer r.polling.Store(false)
	err := w.Poll()
	if errors.Is(err, pcfg.ErrUnchanged) {
		return w.Refused()
	}
	return err
}

// stale reports whether the watcher holds a configuration the server's
// runtime was not built from.
func (r *reloader) stale(w *pcfg.Watcher) bool { return r.loaded.Load() != w.Current() }

func (r *reloader) reload(old, cur *pcfg.Config, warnings pcfg.Problems) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sec := pcfg.Get[Settings](cur, SectionName)
	st, err := sectionSettings(sec)
	if err != nil { // validateFile refused this already
		r.log.Error("configuration change refused; keeping the running configuration", "error", err.Error())
		return
	}
	var applied []string
	if !slices.EqualFunc(st.cookieKeys, r.applied.cookieKeys, func(a, b []byte) bool { return string(a) == string(b) }) {
		if err := r.keys.Rotate(st.cookieKeys); err != nil {
			r.log.Error("configuration change refused; keeping the running cookie keys", "error", err.Error())
			st.cookieKeys = r.applied.cookieKeys
		} else {
			applied = append(applied, "cookie_keys")
		}
	}
	if prev := pcfg.Get[Settings](old, SectionName); prev != nil {
		applied = append(applied, wicketChanges(prev, sec)...)
	}
	louder := st.logLevel < r.applied.logLevel
	quieter := st.logLevel > r.applied.logLevel
	if louder || quieter {
		applied = append(applied, "log_level")
	}
	r.applied.cookieKeys, r.applied.logLevel = st.cookieKeys, st.logLevel
	// The reload is logged at the more verbose of the two levels, so that a
	// change to a quieter one is still seen.
	if louder {
		r.level.Set(st.logLevel)
	}
	for _, p := range warnings {
		r.log.Warn("configuration warning", "problem", p.String())
	}
	restart := restartOnly(r.started, st)
	r.log.Info("configuration reloaded", "applied", applied, "on_restart", restart)
	if len(restart) > 0 {
		r.log.Warn("configuration changes apply when authz gateway restarts", "members", restart)
	}
	if quieter {
		r.level.Set(st.logLevel)
	}
	if r.polling.Load() {
		return // the Load that polled builds this configuration
	}
	select {
	case r.changed <- struct{}{}:
	default: // a rebuild is already due; it reads the newest configuration
	}
}

// wicketChanges lists the members of the wicket file that differ between
// two versions of the section. The serve loop rebuilds the server's
// runtime from them.
func wicketChanges(a, b *Settings) []string {
	var out []string
	for _, m := range []struct {
		name string
		x, y any
	}{
		{"public_url", a.PublicURL, b.PublicURL},
		{"cookie_domain", a.CookieDomain, b.CookieDomain},
		{"session", a.Session, b.Session},
		{"clock_skew", a.ClockSkew, b.ClockSkew},
		{"redirect_hosts", a.RedirectHosts, b.RedirectHosts},
		{"upstream_token_ttl", a.UpstreamTokenTTL, b.UpstreamTokenTTL},
		{"providers", a.Providers, b.Providers},
		{"apps", a.Apps, b.Apps},
	} {
		if !reflect.DeepEqual(m.x, m.y) {
			out = append(out, m.name)
		}
	}
	return out
}

func (r *reloader) refused(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log.Error("configuration change refused; keeping the running configuration", "error", err.Error())
}

// restartOnly lists the members that differ from what the process started
// with and cannot change while it runs.
func restartOnly(a, b settings) []string {
	var out []string
	if a.addr != b.addr {
		out = append(out, "addr")
	}
	if a.adminAddr != b.adminAddr {
		out = append(out, "admin_addr")
	}
	if a.adminToken != b.adminToken {
		out = append(out, "admin_token")
	}
	if a.sessionFile != b.sessionFile {
		out = append(out, "session_file")
	}
	if !slices.Equal(a.signingKeys, b.signingKeys) {
		out = append(out, "signing_keys")
	}
	if !slices.Equal(a.trusted, b.trusted) {
		out = append(out, "trusted_proxies")
	}
	if a.loginRate != b.loginRate {
		out = append(out, "login_rate")
	}
	if a.auditLog != b.auditLog {
		out = append(out, "audit_log")
	}
	if !reflect.DeepEqual(a.http.TLS, b.http.TLS) {
		out = append(out, "tls")
	}
	if a.http.DrainDelay != b.http.DrainDelay || a.http.DrainTimeout != b.http.DrainTimeout {
		out = append(out, "drain")
	}
	return out
}
