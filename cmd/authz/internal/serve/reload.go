package serve

import (
	"errors"
	"log/slog"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/laiwf94/authz/internal/authz/api"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
)

// watchFile loads the serve section of the platform configuration file at
// path and watches it, and the secret files it names, for changes that rl
// applies once the server runs.
func watchFile(path string, getenv func(string) string, rl *reloader) (*pcfg.Watcher, config, error) {
	sc := Schema()
	w, err := pcfg.NewWatcher(sc, path, pcfg.WatchOptions{
		Environ:  sc.Environ(getenv),
		Validate: validateFile,
		OnReload: rl.reload,
		OnError:  rl.refused,
	})
	if err != nil {
		return nil, config{}, err
	}
	cfg, err := settingsConfig(pcfg.Get[Settings](w.Current(), SectionName))
	return w, cfg, err
}

// validateFile refuses a document with no serve section: "authz serve"
// would have nothing to run from.
func validateFile(c *pcfg.Config) error {
	s := pcfg.Get[Settings](c, SectionName)
	if s == nil {
		return errors.New(`$.serve: the file has no serve section (nor any AUTHZ_SERVE_ variable)`)
	}
	_, err := settingsConfig(s)
	return err
}

// grantdVars lists the GRANTD_ variables that are set, which a
// configuration file replaces.
func grantdVars(getenv func(string) string) []string {
	var out []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "GRANTD_") && getenv(k) != "" {
			out = append(out, k)
		}
	}
	for _, k := range []string{"GRANTD_ADDR", "GRANTD_DATA_DIR", "GRANTD_API_KEYS", "GRANTD_TOKEN_KEY", "GRANTD_CACHE_SIZE",
		"GRANTD_RETENTION", "GRANTD_LOG_LEVEL", "GRANTD_AUDIT_LOG", "GRANTD_AUDIT_CHECKS", "GRANTD_KEY_RATE", "GRANTD_KEY_BURST"} {
		if getenv(k) != "" && !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// reloader applies a changed serve section to the running server: the API
// keys and the log level at once, the rest on the next start, which it
// says in the log.
type reloader struct {
	level *slog.LevelVar

	mu      sync.Mutex
	log     *slog.Logger
	srv     *api.Server
	started config // what the process started with
	applied config // the keys and level in use
}

// start hands the reloader the running server. The watcher is started
// after it, so reload and refused always have a server and a log.
func (r *reloader) start(log *slog.Logger, srv *api.Server, cfg config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log, r.srv, r.started, r.applied = log, srv, cfg, cfg
}

func (r *reloader) reload(_, cur *pcfg.Config, warnings pcfg.Problems) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg, err := settingsConfig(pcfg.Get[Settings](cur, SectionName))
	if err != nil { // validateFile refused this already
		r.log.Error("configuration change refused; keeping the running configuration", "error", err.Error())
		return
	}
	var applied []string
	if !slices.Equal(cfg.apiKeys, r.applied.apiKeys) {
		if err := r.srv.SetAPIKeys(cfg.apiKeys); err != nil {
			r.log.Error("configuration change refused; keeping the running API keys", "error", err.Error())
			cfg.apiKeys = r.applied.apiKeys
		} else {
			applied = append(applied, "api_keys")
		}
	}
	louder := cfg.logLevel < r.applied.logLevel
	quieter := cfg.logLevel > r.applied.logLevel
	if louder || quieter {
		applied = append(applied, "log_level")
	}
	r.applied.apiKeys, r.applied.logLevel = cfg.apiKeys, cfg.logLevel
	// The reload is logged at the more verbose of the two levels, so that a
	// change to a quieter one is still seen.
	if louder {
		r.level.Set(cfg.logLevel)
	}
	for _, p := range warnings {
		r.log.Warn("configuration warning", "problem", p.String())
	}
	restart := restartOnly(r.started, cfg)
	r.log.Info("configuration reloaded", "applied", applied, "on_restart", restart)
	if len(restart) > 0 {
		r.log.Warn("configuration changes apply when authz serve restarts", "members", restart)
	}
	if quieter {
		r.level.Set(cfg.logLevel)
	}
}

func (r *reloader) refused(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log.Error("configuration change refused; keeping the running configuration", "error", err.Error())
}

// restartOnly lists the members that differ from what the process started
// with and cannot change while it runs.
func restartOnly(a, b config) []string {
	var out []string
	if a.addr != b.addr {
		out = append(out, "addr")
	}
	if a.dataDir != b.dataDir {
		out = append(out, "data_dir")
	}
	if !slices.EqualFunc(append([][]byte{a.tokenKey}, a.oldTokens...), append([][]byte{b.tokenKey}, b.oldTokens...),
		func(x, y []byte) bool { return string(x) == string(y) }) {
		out = append(out, "token_key")
	}
	if a.cacheSize != b.cacheSize {
		out = append(out, "cache_size")
	}
	if a.retention != b.retention {
		out = append(out, "retention")
	}
	if a.auditLog != b.auditLog {
		out = append(out, "audit_log")
	}
	if a.auditChk != b.auditChk {
		out = append(out, "audit_checks")
	}
	if a.keyLimit.Rate != b.keyLimit.Rate {
		out = append(out, "key_rate")
	}
	if a.keyLimit.Burst != b.keyLimit.Burst {
		out = append(out, "key_burst")
	}
	if !reflect.DeepEqual(a.http.TLS, b.http.TLS) {
		out = append(out, "tls")
	}
	if a.http.DrainDelay != b.http.DrainDelay || a.http.DrainTimeout != b.http.DrainTimeout {
		out = append(out, "drain")
	}
	return out
}
