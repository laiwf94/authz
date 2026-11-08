// Package logging is the one log/slog handler for every authz subcommand.
// It writes JSON lines and adds to every record:
//
//   - subcommand: which subcommand wrote it (serve, gateway, mcp, ...), when
//     the Handler was built with one;
//   - correlation_id: from the context (WithCorrelationID, Middleware), the
//     trace ID of the request's W3C traceparent or a generated one, so a log
//     line, its audit record and the upstream call it makes share one ID;
//   - tenant: from the context (WithTenant) or the Handler's default.
//
// The level is an slog.Leveler, normally an *slog.LevelVar that ReloadLevel
// or LevelHandler change while the process runs. Values are redacted before
// they are encoded: any Secret, attributes whose keys name a secret
// (DefaultSecretKeys and Options.SecretKeys) and struct fields tagged
// `log:"secret"`, at any depth.
//
// Scan and Scanner find keys, tokens and passwords that got through anyway.
// Every record a Handler writes, and every record the audit log appends, is
// handed to the Watchers registered with Watch, which is how the tests and
// the secretscan build check all log and audit output (see the logtest
// package and docs/DESIGN.md, "Secret scan").
package logging

import (
	"context"
	"io"
	"log/slog"
)

// Attribute keys a Handler adds.
const (
	KeySubcommand    = "subcommand"
	KeyCorrelationID = "correlation_id"
	KeyTenant        = "tenant"
)

// Options configure a Handler. The zero value logs at Info.
type Options struct {
	// Level is the minimum level written; an *slog.LevelVar makes it
	// reloadable. Nil means slog.LevelInfo.
	Level slog.Leveler
	// Subcommand, when set, is added to every record.
	Subcommand string
	// Tenant is the tenant added to records whose context has none. Empty
	// means the default tenant, which adds nothing.
	Tenant string
	// SecretKeys are attribute keys redacted in addition to
	// DefaultSecretKeys.
	SecretKeys []string
	// AddSource adds the caller's file and line, as in slog.HandlerOptions.
	AddSource bool
	// ReplaceAttr, when set, runs after redaction, as in
	// slog.HandlerOptions.
	ReplaceAttr func(groups []string, a slog.Attr) slog.Attr
}

// Handler is the slog.Handler New returns.
type Handler struct {
	base   slog.Handler // the JSON handler with the subcommand, no groups
	cur    slog.Handler // base with steps applied
	steps  []step       // WithAttrs and WithGroup calls, in order
	groups bool         // a WithGroup is among steps
	tenant string
	// hasCorr and hasTenant are set when a WithAttrs outside any group
	// already gave the key, so the context's value is not added again.
	hasCorr, hasTenant bool
}

type step struct {
	attrs []slog.Attr
	group string
}

// New returns a Handler writing JSON lines to w.
func New(w io.Writer, opts Options) *Handler {
	red := newRedactor(opts.SecretKeys)
	user := opts.ReplaceAttr
	replace := func(groups []string, a slog.Attr) slog.Attr {
		a = red.replace(groups, a)
		if user != nil {
			a.Value = a.Value.Resolve()
			a = user(groups, a)
		}
		// With a ReplaceAttr set, slog hands over the level as an Any that
		// it then encodes with encoding/json; writing its name here gives
		// the same bytes without that allocation.
		if len(groups) == 0 && a.Key == slog.LevelKey && a.Value.Kind() == slog.KindAny {
			if l, ok := a.Value.Any().(slog.Level); ok {
				a.Value = slog.StringValue(l.String())
			}
		}
		return a
	}
	var base slog.Handler = slog.NewJSONHandler(observed{w}, &slog.HandlerOptions{
		Level:       opts.Level,
		AddSource:   opts.AddSource,
		ReplaceAttr: replace,
	})
	if opts.Subcommand != "" {
		base = base.WithAttrs([]slog.Attr{slog.String(KeySubcommand, opts.Subcommand)})
	}
	return &Handler{base: base, cur: base, tenant: opts.Tenant}
}

// NewLogger returns slog.New(New(w, opts)).
func NewLogger(w io.Writer, opts Options) *slog.Logger { return slog.New(New(w, opts)) }

// Enabled implements slog.Handler.
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.cur.Enabled(ctx, l) }

// Handle implements slog.Handler. The context's correlation ID and tenant
// are added at the top level of the record, outside any group, unless the
// record or the logger already carries that key there.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	var corr, tenant string
	if !h.hasCorr {
		corr = CorrelationID(ctx)
	}
	if !h.hasTenant {
		if tenant = Tenant(ctx); tenant == "" {
			tenant = h.tenant
		}
	}
	if corr == "" && tenant == "" {
		return h.cur.Handle(ctx, r)
	}
	if h.groups {
		// The record's attributes belong inside the open groups, so the
		// context's go on a handler rebuilt with them before the groups.
		var extra []slog.Attr
		if corr != "" {
			extra = append(extra, slog.String(KeyCorrelationID, corr))
		}
		if tenant != "" {
			extra = append(extra, slog.String(KeyTenant, tenant))
		}
		hh := h.base.WithAttrs(extra)
		for _, s := range h.steps {
			hh = s.apply(hh)
		}
		return hh.Handle(ctx, r)
	}
	if r.NumAttrs() > 0 {
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case KeyCorrelationID:
				corr = ""
			case KeyTenant:
				tenant = ""
			}
			return corr != "" || tenant != ""
		})
		if corr == "" && tenant == "" {
			return h.cur.Handle(ctx, r)
		}
	}
	// A new record, so a caller's record (which another handler may also
	// be holding) is never appended to.
	nr := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	if corr != "" {
		nr.AddAttrs(slog.String(KeyCorrelationID, corr))
	}
	if tenant != "" {
		nr.AddAttrs(slog.String(KeyTenant, tenant))
	}
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(a)
		return true
	})
	return h.cur.Handle(ctx, nr)
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	h2 := h.clone()
	s := step{attrs: attrs}
	h2.steps = append(h2.steps, s)
	h2.cur = s.apply(h.cur)
	if !h.groups {
		for _, a := range attrs {
			switch a.Key {
			case KeyCorrelationID:
				h2.hasCorr = true
			case KeyTenant:
				h2.hasTenant = true
			}
		}
	}
	return h2
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h2 := h.clone()
	s := step{group: name}
	h2.steps = append(h2.steps, s)
	h2.cur = s.apply(h.cur)
	h2.groups = true
	return h2
}

func (h *Handler) clone() *Handler {
	h2 := *h
	h2.steps = append([]step(nil), h.steps...)
	return &h2
}

func (s step) apply(h slog.Handler) slog.Handler {
	if s.group != "" {
		return h.WithGroup(s.group)
	}
	return h.WithAttrs(s.attrs)
}
