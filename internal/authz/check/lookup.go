package check

import (
	"context"
	"fmt"
	"sort"

	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
)

// Lister enumerates objects of a type, for lookups.
type Lister interface {
	ObjectIDs(rev store.Revision, resourceType string) ([]string, error)
}

// Lookup limits.
const (
	MaxLookupLimit     = 1000
	DefaultLookupLimit = 100
	// MaxLookupEvaluations caps candidates checked per call; callers page on.
	MaxLookupEvaluations = 10_000
)

// LookupResult is one page of a lookup.
type LookupResult struct {
	// IDs are the objects on which the subject has the permission.
	IDs []string
	// Conditional are the objects on which it has the permission only if
	// the caveat parameters each names allow it, in ID order. A page's
	// limit counts them with IDs.
	Conditional []ConditionalID
	// Next is the cursor to continue from, or "" when the scan is complete.
	Next string
}

// ConditionalID is an object a conditional answer was found for, with the
// caveat parameters it depends on (sorted).
type ConditionalID struct {
	ID      string
	Missing []string
}

// LookupResources returns the IDs of resourceType objects on which subject
// has permission, in ID order, after cursor after. It is
// LookupResourcesContext with no caveat context.
func (e *Engine) LookupResources(ctx context.Context, sc *schema.Schema, l Lister, rev store.Revision,
	resourceType, permission string, subject store.Subject, after string, limit int) (LookupResult, error) {
	return e.LookupResourcesContext(ctx, sc, l, rev, resourceType, permission, subject, after, limit, nil)
}

// LookupResourcesContext returns the IDs of resourceType objects on which
// subject has permission, in ID order, after cursor after: in IDs those
// that CheckResult with caveatCtx allows, in Conditional those it answers
// conditional, with their missing parameters.
//
// It checks each candidate object. That is simple and exactly as correct as
// Check; the cost is linear in the number of objects of the type, which is
// bounded per call by MaxLookupEvaluations and continued through the cursor.
func (e *Engine) LookupResourcesContext(ctx context.Context, sc *schema.Schema, l Lister, rev store.Revision,
	resourceType, permission string, subject store.Subject, after string, limit int, caveatCtx map[string]any) (LookupResult, error) {
	if limit <= 0 {
		limit = DefaultLookupLimit
	}
	if limit > MaxLookupLimit {
		limit = MaxLookupLimit
	}
	probe := Request{ResourceType: resourceType, ResourceID: "probe", Permission: permission, Subject: subject}
	if err := probe.Validate(sc); err != nil {
		return LookupResult{}, err
	}
	rc, err := newRequestContext(caveatCtx)
	if err != nil {
		return LookupResult{}, err
	}
	ids, err := l.ObjectIDs(rev, resourceType)
	if err != nil {
		return LookupResult{}, err
	}
	start := sort.SearchStrings(ids, after)
	if start < len(ids) && ids[start] == after {
		start++
	}
	var out LookupResult
	evaluated, found := 0, 0
	for i := start; i < len(ids); i++ {
		if evaluated == MaxLookupEvaluations {
			out.Next = ids[i-1]
			return out, nil
		}
		evaluated++
		probe.ResourceID = ids[i]
		r, _, err := e.checkValid(ctx, sc, rev, probe, rc)
		if err != nil {
			return LookupResult{}, fmt.Errorf("checking %s:%s: %w", resourceType, ids[i], err)
		}
		switch r.Permissionship {
		case Denied:
			continue
		case Allowed:
			out.IDs = append(out.IDs, ids[i])
		case Conditional:
			out.Conditional = append(out.Conditional, ConditionalID{ID: ids[i], Missing: r.Missing})
		}
		if found++; found == limit {
			if i+1 < len(ids) {
				out.Next = ids[i]
			}
			return out, nil
		}
	}
	return out, nil
}
