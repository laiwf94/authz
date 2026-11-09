// Package part is what a serving subcommand (authz serve, authz gateway,
// authz mcp) takes from the process it runs in. Alone, a subcommand binds
// a listener group and keeps a metrics registry of its own; under
// "authz run" every subcommand joins one httpserver.Shared group and writes
// to one registry, so the process has one readiness flip, one drain and one
// metrics exposition.
package part

import (
	"github.com/laiwf94/authz/internal/platform/httpserver"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

// Host is a subcommand's share of the process. The zero Host is a
// subcommand running alone.
type Host struct {
	// Name, when set, is added to every log line as "subcommand", so the
	// lines of the parts sharing one output can be told apart. Alone, the
	// lines stay as they were.
	Name string
	// Bind binds the subcommand's listeners; nil is httpserver.Bind.
	Bind httpserver.Binder
	// Metrics is the registry the subcommand's metrics go to; nil is a
	// new registry of its own.
	Metrics *metrics.Registry
}

// Binder returns Bind, or httpserver.Bind when it is not set.
func (h Host) Binder() httpserver.Binder {
	if h.Bind == nil {
		return httpserver.Bind
	}
	return h.Bind
}

// Registry returns Metrics, or a new registry when it is not set.
func (h Host) Registry() *metrics.Registry {
	if h.Metrics == nil {
		return metrics.New()
	}
	return h.Metrics
}
