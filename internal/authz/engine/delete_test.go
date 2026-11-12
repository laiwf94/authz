package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/laiwf94/authz/internal/authz/store"
)

func TestDeleteRelationships(t *testing.T) {
	f := newFixture(t, Options{})
	all := store.Filter{ResourceType: "doc", Relation: "viewer"}
	if _, err := f.e.DeleteRelationships(context.Background(), DeleteRequest{Filter: all}); !errors.Is(err, store.ErrNoSchema) {
		t.Fatalf("delete before a schema = %v", err)
	}
	f.schema(t)
	before := f.write(t, "touch doc:a#viewer@user:x", "touch doc:a#viewer@user:y", "touch doc:b#viewer@user:x", "touch doc:a#owner@user:o")

	// Over the limit without allow_partial: refused, nothing deleted.
	if _, err := f.e.DeleteRelationships(context.Background(), DeleteRequest{Filter: all, Limit: 2}); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("over the limit = %v", err)
	}
	if _, err := f.e.DeleteRelationships(context.Background(), DeleteRequest{Filter: all, Limit: -1}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("negative limit = %v", err)
	}
	pre := []store.Precondition{{MustExist: true, Filter: store.Filter{ResourceType: "doc", ResourceID: "nope"}}}
	if _, err := f.e.DeleteRelationships(context.Background(), DeleteRequest{Filter: all, Preconditions: pre}); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("failed precondition = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.e.DeleteRelationships(ctx, DeleteRequest{Filter: all}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled delete = %v", err)
	}
	if f.st.Head() != before.Revision {
		t.Fatalf("refused deletes moved the head from %d to %d", before.Revision, f.st.Head())
	}

	// A page of 2, then the rest. The returned token reads the delete.
	res, err := f.e.DeleteRelationships(context.Background(), DeleteRequest{Filter: all, Limit: 2, AllowPartial: true})
	if err != nil || res.Deleted != 2 || !res.Partial || res.At.Revision != before.Revision+1 || res.At.Token != f.tok.Encode(res.At.Revision) {
		t.Fatalf("first page = %+v, %v", res, err)
	}
	fresh := Consistency{Mode: AtLeastAsFresh, Token: res.At.Token}
	if r := f.check(t, "doc:a", "view", "user:x", fresh); r.Allowed {
		t.Fatal("doc:a#viewer@user:x still allows view after its delete")
	}
	if r := f.check(t, "doc:b", "view", "user:x", fresh); !r.Allowed {
		t.Fatal("doc:b#viewer@user:x was past the page and should remain")
	}
	if r := f.check(t, "doc:a", "view", "user:x", Consistency{Mode: AtExactSnapshot, Token: before.Token}); !r.Allowed {
		t.Fatal("the snapshot before the delete changed")
	}
	res, err = f.e.DeleteRelationships(context.Background(), DeleteRequest{Filter: all, Limit: 2, AllowPartial: true})
	if err != nil || res.Deleted != 1 || res.Partial {
		t.Fatalf("second page = %+v, %v", res, err)
	}
	// Nothing left to match: no new revision.
	head := res.At
	res, err = f.e.DeleteRelationships(context.Background(), DeleteRequest{Filter: all})
	if err != nil || res.Deleted != 0 || res.Partial || res.At != head {
		t.Fatalf("empty delete = %+v, %v", res, err)
	}
	read, err := f.e.ReadRelationships(context.Background(), ReadRequest{Filter: store.Filter{ResourceType: "doc"}, Consistency: Consistency{Mode: FullyConsistent}})
	if err != nil || len(read.Relationships) != 1 || read.Relationships[0].String() != "doc:a#owner@user:o" {
		t.Fatalf("left %v, %v", read.Relationships, err)
	}
}
