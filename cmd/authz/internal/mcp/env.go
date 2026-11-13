package mcp

import (
	"fmt"
	"strings"
)

// The gateway's environment variables keep their toolgate names, so an
// existing deployment starts "authz mcp" unchanged, and each one is also
// accepted under the platform's AUTHZ_MCP_ prefix.
const (
	legacyPrefix = "TOOLGATE_"
	newPrefix    = "AUTHZ_MCP_"
)

// gatewayEnv lists the variable suffixes that have both names. Upstream
// credentials are not here: they are read under whatever name the config
// gives in credential_env.
var gatewayEnv = []string{
	"ADDR", "ADMIN_ADDR", "ADMIN_TOKEN", "CONFIG", "POLICY", "AUDIT_LOG", "AUDIT_KEY",
	"STATE_DIR", "SIGNING_KEYS", "ALLOWED_ORIGINS", "POLICY_POLL", "LOG_LEVEL",
	"TLS_CERT", "TLS_KEY", "TLS_CLIENT_CA", "DRAIN_DELAY", "DRAIN_TIMEOUT",
	"KEYS_FILE", "SIGNING_ROTATE_EVERY", "SIGNING_OVERLAP",
}

// compatEnv returns a getenv that answers each TOOLGATE_<suffix> lookup with
// AUTHZ_MCP_<suffix> when that is set and with TOOLGATE_<suffix> otherwise.
// Every other name passes through. Both names set to different values is an
// error rather than a silent choice, so a half-migrated deployment fails at
// start instead of running with the value the operator did not mean.
func compatEnv(getenv func(string) string, suffixes []string) (func(string) string, error) {
	known := make(map[string]string, 2*len(suffixes))
	var conflicts []string
	for _, s := range suffixes {
		old, cur := getenv(legacyPrefix+s), getenv(newPrefix+s)
		if old != "" && cur != "" && old != cur {
			conflicts = append(conflicts, newPrefix+s+" and "+legacyPrefix+s)
		}
		v := old
		if cur != "" {
			v = cur
		}
		known[legacyPrefix+s], known[newPrefix+s] = v, v
	}
	if len(conflicts) > 0 {
		return nil, fmt.Errorf("%s set to different values; unset one name of each pair", strings.Join(conflicts, ", "))
	}
	return func(k string) string {
		if v, ok := known[k]; ok {
			return v
		}
		return getenv(k)
	}, nil
}

// aliasHint names the AUTHZ_MCP_ spelling of a TOOLGATE_ variable for error
// messages, so either name leads the operator to the setting.
func aliasHint(name string) string {
	if rest, ok := strings.CutPrefix(name, legacyPrefix); ok {
		return " (or " + newPrefix + rest + ")"
	}
	return ""
}
