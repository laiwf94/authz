package check

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
)

// Permissionship is the answer to a check.
type Permissionship uint8

// Answers. Conditional means the answer depends on caveat parameters the
// check did not supply: supplying them may give either answer.
const (
	Denied Permissionship = iota
	Allowed
	Conditional
)

func (p Permissionship) String() string {
	switch p {
	case Allowed:
		return "allowed"
	case Conditional:
		return "conditional"
	}
	return "denied"
}

// Result is the answer to a check. Missing names, in order, the caveat
// parameters a Conditional answer depends on; it is empty otherwise.
type Result struct {
	Permissionship Permissionship
	Missing        []string
}

// Allowed reports whether the subject has the permission whatever the
// missing parameters are.
func (r Result) Allowed() bool { return r.Permissionship == Allowed }

var (
	allowed = Result{Permissionship: Allowed}
	denied  = Result{Permissionship: Denied}
)

// Limits on caveats in one check.
const (
	// MaxCaveatCostPerCheck bounds the total CEL cost of the caveats one
	// check, or one page of a subject lookup, evaluates. Each evaluation is
	// also bounded by the caveat's own limit (cel.DefaultMaxCost).
	MaxCaveatCostPerCheck = 1_000_000
	// MaxContextSize bounds a check's context, in bytes of its JSON
	// encoding.
	MaxContextSize = 16 << 10
)

// ErrCaveat wraps the failure of a caveat expression at check time: a
// context value of the wrong type for a parameter, or a runtime error
// such as a missing map key.
var ErrCaveat = errors.New("caveat evaluation failed")

// eachDirect calls fn for each relationship stored on typ:id#rel at rev,
// with its caveat (nil for none). A schema that declares no caveats can
// hold no caveated relationship, so it reads through ReadDirect, which
// does not carry the caveat pointers.
func (e *Engine) eachDirect(sc *schema.Schema, rev store.Revision, typ, id, rel string, fn func(store.Caveated) error) error {
	if len(sc.Caveats) == 0 {
		rels, err := e.r.ReadDirect(rev, typ, id, rel)
		if err != nil {
			return err
		}
		for _, r := range rels {
			if err := fn(store.Caveated{Relationship: r}); err != nil {
				return err
			}
		}
		return nil
	}
	rels, err := e.r.ReadDirectCaveated(rev, typ, id, rel)
	if err != nil {
		return err
	}
	for _, r := range rels {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

// allowsCaveat reports whether the current schema lets rel hold r with
// the caveat it carries. One that it does not (only possible at a
// snapshot older than a schema change) grants nothing.
func allowsCaveat(sc *schema.Schema, rel *schema.Relation, r store.Caveated) bool {
	if r.Caveat == nil {
		return true
	}
	_, known := sc.Caveats[r.Caveat.Name]
	return known && rel != nil && rel.AllowsCaveat(r.SubjectType, r.SubjectID, r.SubjectRelation, r.Caveat.Name)
}

// or is the union of two answers: allowed if either is, conditional if
// either is and neither is allowed.
func or(a, b Result) Result {
	switch {
	case a.Permissionship == Allowed || b.Permissionship == Denied:
		return a
	case b.Permissionship == Allowed || a.Permissionship == Denied:
		return b
	}
	return Result{Permissionship: Conditional, Missing: mergeNames(a.Missing, b.Missing)}
}

// and is the intersection of two answers: denied if either is, allowed
// if both are.
func and(a, b Result) Result {
	switch {
	case a.Permissionship == Denied || b.Permissionship == Allowed:
		return a
	case b.Permissionship == Denied || a.Permissionship == Allowed:
		return b
	}
	return Result{Permissionship: Conditional, Missing: mergeNames(a.Missing, b.Missing)}
}

// not inverts an answer; a conditional answer stays conditional on the
// same parameters.
func not(a Result) Result {
	switch a.Permissionship {
	case Allowed:
		return denied
	case Denied:
		return allowed
	}
	return a
}

// mergeNames returns the sorted union of two sorted name lists, sharing
// one of them when the other adds nothing. Lists are never modified once
// made, so results can share them.
func mergeNames(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	if len(a) == 0 {
		return b
	}
	out := make([]string, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] < b[j]:
			out = append(out, a[i])
			i++
		case a[i] > b[j]:
			out = append(out, b[j])
			j++
		default:
			out = append(out, a[i])
			i, j = i+1, j+1
		}
	}
	out = append(out, a[i:]...)
	out = append(out, b[j:]...)
	if len(out) == len(a) {
		return a
	}
	if len(out) == len(b) {
		return b
	}
	return out
}

// requestContext is a check's context in the form caveats see it: encoded
// and decoded again with numbers as json.Number, exactly as a stored
// context is, and hashed for cache keys.
type requestContext struct {
	vals map[string]any // nil for none
	hash string         // "-" for none
}

// ValidateContext reports whether ctx is acceptable as a check's caveat
// context: it encodes as JSON, within MaxContextSize. The error matches
// store.ErrInvalid. CheckResult runs the same validation; other engines
// use this to refuse the same contexts.
func ValidateContext(ctx map[string]any) error {
	_, err := newRequestContext(ctx)
	return err
}

func newRequestContext(ctx map[string]any) (requestContext, error) {
	if len(ctx) == 0 {
		return requestContext{hash: "-"}, nil
	}
	enc, err := json.Marshal(ctx)
	if err != nil {
		return requestContext{}, fmt.Errorf("%w: context: %v", store.ErrInvalid, err)
	}
	if len(enc) > MaxContextSize {
		return requestContext{}, fmt.Errorf("%w: context is %d bytes encoded (max %d)", store.ErrInvalid, len(enc), MaxContextSize)
	}
	d := json.NewDecoder(bytes.NewReader(enc))
	d.UseNumber()
	var vals map[string]any
	if err := d.Decode(&vals); err != nil {
		return requestContext{}, fmt.Errorf("%w: context: %v", store.ErrInvalid, err)
	}
	// Encoding the decoded form gives canonical JSON: sorted keys and
	// numbers as written, so equal contexts hash equal.
	if enc, err = json.Marshal(vals); err != nil {
		return requestContext{}, fmt.Errorf("%w: context: %v", store.ErrInvalid, err)
	}
	sum := sha256.Sum256(enc)
	return requestContext{vals: vals, hash: base64.RawStdEncoding.EncodeToString(sum[:16])}, nil
}

// caveat evaluates the caveat r carries for a check, counting it so the
// node knows its result depended on the context.
func (s *state) caveat(rel *schema.Relation, r store.Caveated) (Result, error) {
	res, evaluated, err := evalCaveat(s.sc, s.reqCtx, rel, r, &s.stats)
	if evaluated {
		s.caveats++
	}
	return res, err
}

// evalCaveat evaluates the caveat r carries, with its stored context over
// the request's, and counts it in st. A relationship without a caveat is
// allowed without evaluating anything; one the current schema does not let
// rel hold with that caveat (see allowsCaveat) is denied. evaluated
// reports that the caveat's expression ran.
func evalCaveat(sc *schema.Schema, reqCtx requestContext, rel *schema.Relation, r store.Caveated, st *Stats) (res Result, evaluated bool, err error) {
	c := r.Caveat
	if c == nil {
		return allowed, false, nil
	}
	if !allowsCaveat(sc, rel, r) {
		return denied, false, nil
	}
	cv := sc.Caveats[c.Name]
	st.Caveats++
	vars := reqCtx.vals
	if len(c.Context) > 0 {
		vars = make(map[string]any, len(c.Context)+len(reqCtx.vals))
		for k, v := range reqCtx.vals {
			vars[k] = v
		}
		for k, v := range c.Context {
			vars[k] = v
		}
	}
	out, err := cv.Program.Eval(vars)
	st.CaveatCost += int(out.Cost)
	if err != nil {
		return denied, true, fmt.Errorf("%w: %s on %s: %v", ErrCaveat, c.Name, r.Relationship, err)
	}
	if st.CaveatCost > MaxCaveatCostPerCheck {
		return denied, true, ErrTooMuchWork
	}
	if !out.Known() {
		return Result{Permissionship: Conditional, Missing: slices.Clip(out.Missing)}, true, nil
	}
	b, isBool := out.Value.(bool)
	if !isBool {
		return denied, true, fmt.Errorf("%w: %s on %s gave %T, not bool", ErrCaveat, c.Name, r.Relationship, out.Value)
	}
	if b {
		return allowed, true, nil
	}
	return denied, true, nil
}
