package mcp

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/agents/gateway"
	"github.com/laiwf94/authz/internal/agents/policy"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/httpserver"
)

// ConfigEnv names the platform configuration file when -config is not
// given. It is not one of the gateway's own variables: TOOLGATE_CONFIG and
// AUTHZ_MCP_CONFIG name the agents config, $.mcp.config in the file.
const ConfigEnv = "AUTHZ_CONFIG"

// OtherSections are the sections of the platform file that belong to the
// other long-running subcommands. "authz mcp serve -config" reads past
// them, so one file can configure every subcommand and a problem in
// another's section does not stop this one.
var OtherSections = []string{"serve", "gateway"}

// Schema is what "authz mcp serve -config" reads: its own section, with
// getenv resolving the upstream credentials the agents config names, and
// the others skipped.
func Schema(getenv func(string) string) *pcfg.Schema {
	secs := []pcfg.Section{Section(getenv)}
	for _, name := range OtherSections {
		secs = append(secs, pcfg.Skip(name))
	}
	return pcfg.MustSchema(secs...)
}

// serveArgs reads the arguments of "serve": -config file, or
// $AUTHZ_CONFIG. ok is false when the command should exit with code
// instead (help, or a usage error, already printed).
func serveArgs(prog string, args []string, getenv func(string) string, stderr io.Writer) (path string, code int, ok bool) {
	if len(args) == 0 {
		return getenv(ConfigEnv), 0, true
	}
	fs := flag.NewFlagSet(prog+" serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usageFor(prog)) }
	file := fs.String("config", "", "platform configuration file (default $"+ConfigEnv+")")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", 0, false
		}
		return "", 2, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s serve: unexpected argument %q; configuration comes from -config or the environment\n", prog, fs.Arg(0))
		return "", 2, false
	}
	if *file == "" {
		*file = getenv(ConfigEnv)
	}
	return *file, 0, true
}

// sectionConfig is the configuration a checked section starts the gateway
// with, the same one loadConfig builds from the TOOLGATE_ variables.
func sectionConfig(s *Settings) (config, error) {
	c := config{addr: s.Addr, adminAddr: s.AdminAddr, adminToken: s.AdminToken.Value(), configPath: s.Config,
		policyPath: s.Policy, auditPath: s.AuditLog, stateDir: s.StateDir, poll: time.Duration(s.PolicyPoll)}
	var err error
	if c.auditKey, err = hex.DecodeString(s.AuditKey.Value()); err != nil || len(c.auditKey) != 32 {
		return c, errors.New("$.mcp.audit_key must be 64 hex characters")
	}
	if c.keys, c.activeKey, err = parseKeys(s.SigningKeys.Value()); err != nil {
		return c, fmt.Errorf("$.mcp.signing_keys %s", strings.TrimPrefix(err.Error(), legacyPrefix+"SIGNING_KEYS "))
	}
	for _, o := range s.AllowedOrigins {
		if o = strings.TrimSpace(o); o != "" {
			c.origins = append(c.origins, o)
		}
	}
	if err := c.logLevel.UnmarshalText([]byte(s.LogLevel)); err != nil {
		return c, fmt.Errorf("$.mcp.log_level: %v", err)
	}
	if s.agents == nil || s.auth == nil {
		// The check builds both whenever the section has no errors.
		return c, errors.New("$.mcp.config: the agents config was not checked")
	}
	c.http = httpserver.Options{TLS: s.tlsFiles(), DrainDelay: time.Duration(s.DrainDelay), DrainTimeout: time.Duration(s.DrainTimeout)}
	return c, nil
}

func (s *Settings) tlsFiles() *httpserver.TLSFiles {
	if s.TLSCert == "" || s.TLSKey == "" {
		return nil
	}
	return &httpserver.TLSFiles{CertFile: s.TLSCert, KeyFile: s.TLSKey, ClientCAFile: s.TLSClientCA}
}

// watchFile loads the mcp section of the platform configuration file at
// path and watches it, the secret files it names, the agents config and
// the policy, for changes that rl applies once the gateway runs.
func watchFile(path string, getenv func(string) string, rl *reloader) (*pcfg.Watcher, *Settings, config, error) {
	sc := Schema(getenv)
	w, err := pcfg.NewWatcher(sc, path, pcfg.WatchOptions{
		Environ:  sc.Environ(getenv),
		Validate: validateFile,
		OnReload: rl.reload,
		OnError:  rl.refused,
	})
	if err != nil {
		return nil, nil, config{}, err
	}
	s := pcfg.Get[Settings](w.Current(), SectionName)
	cfg, err := sectionConfig(s)
	return w, s, cfg, err
}

// validateFile refuses a document with no mcp section: "authz mcp serve"
// would have nothing to run from.
func validateFile(c *pcfg.Config) error {
	s := pcfg.Get[Settings](c, SectionName)
	if s == nil {
		return errors.New(`$.mcp: the file has no mcp section (nor any AUTHZ_MCP_ variable)`)
	}
	_, err := sectionConfig(s)
	return err
}

// toolgateVars lists the TOOLGATE_ variables that are set, which a
// configuration file replaces. Only the gateway's own names are listed:
// an upstream credential may be called anything, TOOLGATE_ names
// included, and is still read under that name.
func toolgateVars(getenv func(string) string) []string {
	var out []string
	for _, s := range gatewayEnv {
		if getenv(legacyPrefix+s) != "" {
			out = append(out, legacyPrefix+s)
		}
	}
	slices.Sort(out)
	return out
}

// reloader applies a changed mcp section to the running gateway: the
// agents, token settings and limits of the agents config and the signing
// keys through gateway.SetAgents, the policy through its store, and the
// log level, all at once. The members that cannot change while the gateway
// runs are logged as applying on restart.
type reloader struct {
	level *slog.LevelVar

	mu            sync.Mutex
	log           *slog.Logger
	gw            *gateway.Gateway
	pol           *policy.Store
	started       config          // what the process started with
	startedAgents *gateway.Config // the agents config it started with
	applied       config          // the signing keys and level in use
	appliedAgents *gateway.Config // the agents in use
	policyHash    string          // the policy the last reload saw in force
}

// start hands the reloader the running gateway. The watcher is started
// after it, so reload and refused always have a gateway and a log.
func (r *reloader) start(log *slog.Logger, gw *gateway.Gateway, pol *policy.Store, cfg config, gc *gateway.Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log, r.gw, r.pol = log, gw, pol
	r.started, r.applied = cfg, cfg
	r.startedAgents, r.appliedAgents = gc, gc
	r.policyHash = pol.Current().Hash
}

func (r *reloader) reload(_, cur *pcfg.Config, warnings pcfg.Problems) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := pcfg.Get[Settings](cur, SectionName)
	cfg, err := sectionConfig(s)
	if err != nil { // validateFile refused this already
		r.log.Error("configuration change refused; keeping the running configuration", "error", err.Error())
		return
	}
	var applied []string
	agentsChanged := !sameAgents(r.appliedAgents, s.agents)
	keysChanged := !sameKeys(r.applied, cfg)
	if agentsChanged || keysChanged {
		if err := r.gw.SetAgents(s.agents, s.auth); err != nil {
			r.log.Error("configuration change refused; keeping the running agents", "error", err.Error())
		} else {
			if agentsChanged {
				applied = append(applied, "config")
			}
			if keysChanged {
				applied = append(applied, "signing_keys")
			}
			r.appliedAgents = s.agents
			r.applied.keys, r.applied.activeKey = cfg.keys, cfg.activeKey
		}
	}
	// The check read the policy and found it valid; the store reads it
	// again and applies it unless its own poll already has.
	r.pol.Poll()
	if h := r.pol.Current().Hash; h != r.policyHash {
		applied = append(applied, "policy")
		r.policyHash = h
	}
	louder := cfg.logLevel < r.applied.logLevel
	quieter := cfg.logLevel > r.applied.logLevel
	if louder || quieter {
		applied = append(applied, "log_level")
	}
	r.applied.logLevel = cfg.logLevel
	// The reload is logged at the more verbose of the two levels, so that a
	// change to a quieter one is still seen.
	if louder {
		r.level.Set(cfg.logLevel)
	}
	for _, p := range warnings {
		r.log.Warn("configuration warning", "problem", p.String())
	}
	restart := restartOnly(r.started, cfg, r.startedAgents, s.agents)
	r.log.Info("configuration reloaded", "applied", applied, "on_restart", restart)
	if len(restart) > 0 {
		r.log.Warn("configuration changes apply when authz mcp restarts", "members", restart)
	}
	if quieter {
		r.level.Set(cfg.logLevel)
	}
}

// refused logs a change the watcher would not load. The policy store
// looks at its file too: when the policy is what broke the change, it is
// rejected there as well, with its own log line, metric and audit record,
// as the store's poll would.
func (r *reloader) refused(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log.Error("configuration change refused; keeping the running configuration", "error", err.Error())
	r.pol.Poll()
	r.policyHash = r.pol.Current().Hash
}

// sameAgents reports whether two agents configs agree on everything
// SetAgents puts in force.
func sameAgents(a, b *gateway.Config) bool {
	return reflect.DeepEqual(a.Agents, b.Agents) && reflect.DeepEqual(a.Tokens, b.Tokens) && a.Limits == b.Limits
}

func sameKeys(a, b config) bool {
	return a.activeKey == b.activeKey && maps.EqualFunc(a.keys, b.keys, func(x, y []byte) bool { return string(x) == string(y) })
}

// restartOnly lists the members that differ from what the process started
// with and cannot change while it runs.
func restartOnly(a, b config, ga, gb *gateway.Config) []string {
	var out []string
	add := func(changed bool, name string) {
		if changed {
			out = append(out, name)
		}
	}
	add(a.addr != b.addr, "addr")
	add(a.adminAddr != b.adminAddr, "admin_addr")
	add(a.adminToken != b.adminToken, "admin_token")
	add(!reflect.DeepEqual(ga.Upstreams, gb.Upstreams), "config.upstreams")
	add(ga.Approvals != gb.Approvals, "config.approvals")
	add(a.policyPath != b.policyPath, "policy")
	add(a.auditPath != b.auditPath, "audit_log")
	add(string(a.auditKey) != string(b.auditKey), "audit_key")
	add(a.stateDir != b.stateDir, "state_dir")
	add(!slices.Equal(a.origins, b.origins), "allowed_origins")
	add(a.poll != b.poll, "policy_poll")
	add(!reflect.DeepEqual(a.http.TLS, b.http.TLS), "tls")
	add(a.http.DrainDelay != b.http.DrainDelay || a.http.DrainTimeout != b.http.DrainTimeout, "drain")
	return out
}
