package engine

import (
	"context"

	"github.com/laiwf94/authz/internal/authz/check"
)

// Explain answers a CheckRequest as Check does, at the snapshot its
// consistency selects, with a trace of the evaluation of at most maxNodes
// nodes (check.DefaultTraceNodes when maxNodes <= 0, never more than
// check.MaxTraceNodes). The shared result cache is not read, so the trace
// shows the reasoning rather than a cache hit; results are still written
// to it. Dispatches and caveats count toward the engine's metrics, but the
// evaluation is not observed as a check's latency. On error the trace is
// nil.
func (e *Local) Explain(ctx context.Context, req CheckRequest, maxNodes int) (CheckResult, *check.Trace, error) {
	rev, err := e.resolve(req.Consistency)
	if err != nil {
		return CheckResult{}, nil, err
	}
	sc, _ := e.st.Schema()
	r, tr, stats, err := e.eng.ExplainResult(ctx, sc, rev, check.Request{ResourceType: req.ResourceType,
		ResourceID: req.ResourceID, Permission: req.Permission, Subject: req.Subject}, req.Context, maxNodes)
	e.dispatches.Add(uint64(stats.Dispatches))
	e.countCaveats(stats)
	if err != nil {
		return CheckResult{}, nil, err
	}
	return CheckResult{Allowed: r.Allowed(), Permissionship: r.Permissionship, Missing: r.Missing, At: e.at(rev)}, tr, nil
}
