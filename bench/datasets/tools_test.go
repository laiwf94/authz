package datasets

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/laiwf94/authz/internal/agents/schema"
)

// TestCatalogCallsAreValid compiles every tool's input schema with the
// gateway's own validator and checks every call's arguments against it,
// after a JSON round trip as they travel.
func TestCatalogCallsAreValid(t *testing.T) {
	tools, err := Catalog(2_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	compiled := map[string]*schema.Schema{}
	for _, tl := range tools {
		if compiled[tl.Name] != nil {
			t.Fatalf("tool name %s repeats", tl.Name)
		}
		raw, _ := json.Marshal(tl.InputSchema)
		s, err := schema.Compile(raw)
		if err != nil {
			t.Fatalf("%s: %v: %s", tl.Name, err, raw)
		}
		compiled[tl.Name] = s
		if len(tl.Description) < 20 {
			t.Errorf("%s: description %q", tl.Name, tl.Description)
		}
	}
	calls, err := Calls(tools, 5_000, 2)
	if err != nil {
		t.Fatal(err)
	}
	hits := map[string]int{}
	for _, c := range calls {
		raw, _ := json.Marshal(c.Arguments)
		// Numbers arrive as json.Number, as the gateway decodes them.
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var args any
		if err := dec.Decode(&args); err != nil {
			t.Fatal(err)
		}
		if err := compiled[c.Name].Validate(args); err != nil {
			t.Fatalf("call of %s with %s: %v", c.Name, raw, err)
		}
		hits[c.Name]++
	}
	// Popular tools are called most; most of the catalog rarely.
	if hits[tools[0].Name] < 100 || len(hits) < 200 {
		t.Errorf("first tool called %d times, %d distinct tools called", hits[tools[0].Name], len(hits))
	}
	// Negative control: the validator does refuse a wrong call.
	if compiled[tools[0].Name].Validate(map[string]any{"not_an_argument": true}) == nil {
		t.Error("the validator accepts anything; the check above proves nothing")
	}
}

func TestCatalogIsSeeded(t *testing.T) {
	a, _ := Catalog(300, 5)
	b, _ := Catalog(300, 5)
	c, _ := Catalog(300, 6)
	if !reflect.DeepEqual(a, b) || reflect.DeepEqual(a, c) {
		t.Error("catalogs do not follow the seed")
	}
	ca, _ := Calls(a, 100, 1)
	cb, _ := Calls(b, 100, 1)
	if !reflect.DeepEqual(ca, cb) {
		t.Error("calls do not follow the seed")
	}
	one, err := Calls(a[:1], 3, 1)
	if err != nil || len(one) != 3 || one[2].Name != a[0].Name {
		t.Errorf("calls of a one-tool catalog: %v, %v", one, err)
	}
}

func TestToolNames(t *testing.T) {
	pairs := len(toolVerbs) * len(toolNouns)
	for n, want := range map[int]string{0: "get_issue", 1: "list_issue", len(toolVerbs): "get_ticket",
		pairs: "get_issue_2", 2*pairs + 1: "list_issue_3"} {
		if got := ToolName(n); got != want {
			t.Errorf("ToolName(%d) = %s, want %s", n, got, want)
		}
	}
	for _, n := range []int{0, MaxTools + 1} {
		if _, err := Catalog(n, 1); err == nil {
			t.Errorf("Catalog(%d) accepted", n)
		}
	}
	if _, err := Calls(nil, 1, 1); err == nil {
		t.Error("calls of no tools accepted")
	}
	tools, _ := Catalog(1, 1)
	tools[0].InputSchema["properties"] = map[string]any{"x": "not a schema"}
	tools[0].InputSchema["required"] = []any{"x"}
	if _, err := Calls(tools, 1, 1); err == nil {
		t.Error("a broken schema gave calls")
	}
	tools[0].InputSchema["properties"] = map[string]any{"x": map[string]any{"type": "object"}}
	if _, err := Calls(tools, 1, 1); err == nil {
		t.Error("an unknown argument type gave calls")
	}
}
