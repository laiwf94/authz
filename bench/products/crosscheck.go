package products

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/laiwf94/authz/bench/datasets"
)

// Question is one sampled check.
type Question struct {
	Resource   string `json:"resource"`
	Permission string `json:"permission"`
	Subject    string `json:"subject"`
}

func (q Question) String() string { return q.Resource + "#" + q.Permission + "@" + q.Subject }

// Sample draws n checks on g's documents from seed. Two in three ask view
// or edit for a uniformly drawn document and user, so they cover the whole
// graph and mostly come out as the folder trees and groups decide. The
// third asks about a document relationship found at a drawn place in the
// graph (an owner, an editor, a banned user, an editing group's member),
// so that the answers the schema gives directly, and bans subtracting
// from them, come up often.
func Sample(g datasets.Graph, n int, seed uint64) []Question {
	r := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15))
	qs := make([]Question, 0, n)
	count := g.Count()
	for i := range n {
		perm := "view"
		if r.IntN(4) == 0 {
			perm = "edit"
		}
		q := Question{Resource: "doc:" + datasets.ObjectID(datasets.TypeDoc, r.IntN(g.Docs)),
			Permission: perm, Subject: "user:" + datasets.ObjectID(datasets.TypeUser, r.IntN(g.Users))}
		if i%3 == 2 {
			if rel, ok := docRelationship(g, r.Int64N(count)); ok {
				q.Resource = "doc:" + datasets.ObjectID(datasets.TypeDoc, rel.Resource)
				q.Subject = string(datasets.AppendObject(nil, rel.SubjectType, rel.Subject))
				if rel.SubjectRelation != "" {
					q.Subject += "#" + rel.SubjectRelation
				}
			}
		}
		qs = append(qs, q)
	}
	return qs
}

// docRelationship is the first relationship from position at on whose
// resource is a document and whose subject is not a folder.
func docRelationship(g datasets.Graph, at int64) (datasets.Relationship, bool) {
	var found datasets.Relationship
	ok := false
	stop := fmt.Errorf("found")
	_ = g.EachRange(at, min(at+4096, g.Count()), func(r *datasets.Relationship) error {
		if r.ResourceType == datasets.TypeDoc && r.SubjectType != datasets.TypeFolder {
			found, ok = *r, true
			return stop
		}
		return nil
	})
	return found, ok
}

// Disagreement is a question two targets answered differently.
type Disagreement struct {
	Question Question        `json:"question"`
	Answers  map[string]bool `json:"answers"`
}

// Report is what CrossCheck found.
type Report struct {
	Questions int `json:"questions"`
	// Allowed is how many questions every target allowed.
	Allowed       int            `json:"allowed"`
	Disagreements []Disagreement `json:"disagreements,omitempty"`
}

// CrossCheck asks every target each question, workers questions at a
// time, with fresh reads. It returns an error when a check fails, and
// lists every question the targets answered differently.
func CrossCheck(ctx context.Context, targets []Target, qs []Question, workers int) (Report, error) {
	if len(targets) < 2 {
		return Report{}, fmt.Errorf("cross-check needs two targets or more, got %d", len(targets))
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	answers := make([][]bool, len(qs))
	var next atomic.Int64
	var wg sync.WaitGroup
	for range max(workers, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(qs) || ctx.Err() != nil {
					return
				}
				q := qs[i]
				row := make([]bool, len(targets))
				for j, t := range targets {
					ok, err := t.Check(ctx, q.Resource, q.Permission, q.Subject, true)
					if err != nil {
						cancel(fmt.Errorf("%s: %s: %w", t.Name(), q, err))
						return
					}
					row[j] = ok
				}
				answers[i] = row
			}
		}()
	}
	wg.Wait()
	if err := context.Cause(ctx); err != nil {
		return Report{}, err
	}
	rep := Report{Questions: len(qs)}
	for i, row := range answers {
		same := true
		for _, a := range row[1:] {
			same = same && a == row[0]
		}
		if same {
			if row[0] {
				rep.Allowed++
			}
			continue
		}
		d := Disagreement{Question: qs[i], Answers: map[string]bool{}}
		for j, t := range targets {
			d.Answers[t.Name()] = row[j]
		}
		rep.Disagreements = append(rep.Disagreements, d)
	}
	return rep, nil
}

// String is a one-line summary of the report.
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d questions, %d allowed by all, %d disagreements", r.Questions, r.Allowed, len(r.Disagreements))
	for i, d := range r.Disagreements {
		if i == 5 {
			fmt.Fprintf(&b, "; and %d more", len(r.Disagreements)-5)
			break
		}
		fmt.Fprintf(&b, "; %s: %v", d.Question, d.Answers)
	}
	return b.String()
}
