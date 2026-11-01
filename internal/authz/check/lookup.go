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
	IDs []string
	// Next is the cursor to continue from, or "" when the scan is complete.
	Next string
}

// LookupResources returns the IDs of resourceType objects on which subject
// has permission, in ID order, after cursor after.
//
// It checks each candidate object. That is simple and exactly as correct as
// Check; the cost is linear in the number of objects of the type, which is
// bounded per call by MaxLookupEvaluations and continued through the cursor.
func (e *Engine) LookupResources(ctx context.Context, sc *schema.Schema, l Lister, rev store.Revision,
	resourceType, permission string, subject store.Subject, after string, limit int) (LookupResult, error) {
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
	ids, err := l.ObjectIDs(rev, resourceType)
	if err != nil {
		return LookupResult{}, err
	}
	start := sort.SearchStrings(ids, after)
	if start < len(ids) && ids[start] == after {
		start++
	}
	var out LookupResult
	evaluated := 0
	for i := start; i < len(ids); i++ {
		if evaluated == MaxLookupEvaluations {
			out.Next = ids[i-1]
			return out, nil
		}
		evaluated++
		ok, _, err := e.Check(ctx, sc, rev, Request{ResourceType: resourceType, ResourceID: ids[i], Permission: permission, Subject: subject})
		if err != nil {
			return LookupResult{}, fmt.Errorf("checking %s:%s: %w", resourceType, ids[i], err)
		}
		if !ok {
			continue
		}
		out.IDs = append(out.IDs, ids[i])
		if len(out.IDs) == limit {
			if i+1 < len(ids) {
				out.Next = ids[i]
			}
			return out, nil
		}
	}
	return out, nil
}
