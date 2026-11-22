package datasets

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
)

// Tool is one MCP tool definition, as a tools/list result lists it.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Call is one tools/call request in authzbench's -mcp-tools list.
type Call struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// MaxTools bounds Catalog.
const MaxTools = 100_000

var (
	toolVerbs = []string{"get", "list", "search", "create", "update", "delete", "export", "summarize",
		"assign", "close", "comment_on", "archive"}
	toolNouns = []string{"issue", "ticket", "document", "folder", "invoice", "order", "customer", "contact",
		"meeting", "message", "channel", "report", "dashboard", "deployment", "build", "release", "alert",
		"incident", "page", "record", "file", "calendar_event", "task", "project", "repository",
		"pull_request", "branch", "user", "group", "role", "policy", "secret_ref", "dataset", "query",
		"table", "metric", "trace", "log_stream", "queue", "note"}
	words = []string{"the", "a", "matching", "selected", "current", "owner's", "team", "workspace", "recent",
		"archived", "open", "shared", "by", "with", "for", "from", "each", "every", "named", "given", "and",
		"its", "related", "items", "fields", "status", "details", "returns", "within", "scope"}
	// argument kinds and the names that go with them.
	argNames = map[string][]string{
		"string":  {"query", "title", "body", "name", "path", "comment", "label", "owner", "cursor", "note"},
		"id":      {"id", "parent_id", "project_id", "workspace_id", "assignee_id"},
		"integer": {"limit", "offset", "page", "priority", "days", "count"},
		"boolean": {"include_archived", "dry_run", "notify", "recursive", "exact"},
		"enum":    {"status", "sort", "visibility", "format", "severity"},
		"array":   {"tags", "fields", "labels", "ids"},
	}
	argKinds   = []string{"string", "id", "integer", "boolean", "enum", "array"}
	enumValues = []string{"open", "closed", "draft", "pending", "done", "low", "medium", "high", "asc", "desc",
		"public", "private", "json", "csv"}
)

// ToolName is the name of tool n: verb_noun, with a numbered suffix once
// every pair is taken.
func ToolName(n int) string {
	v, k := toolVerbs[n%len(toolVerbs)], n/len(toolVerbs)
	name := v + "_" + toolNouns[k%len(toolNouns)]
	if round := k / len(toolNouns); round > 0 {
		name += "_" + strconv.Itoa(round+1)
	}
	return name
}

// Catalog returns n tools. Each has one to six arguments of string, ID,
// integer, boolean, enum and string-list kinds with bounds, a closed
// object schema with one or two required arguments, and a description of
// ten to forty words, as tools of real servers have.
func Catalog(n int, seed uint64) ([]Tool, error) {
	if n < 1 || n > MaxTools {
		return nil, fmt.Errorf("tools: %d, want 1 to %d", n, MaxTools)
	}
	pcg := rand.NewPCG(0, 0)
	r := rand.New(pcg)
	out := make([]Tool, n)
	for i := range out {
		pcg.Seed(seed, kindTool<<56^uint64(i))
		name := ToolName(i)
		var desc strings.Builder
		desc.WriteString(strings.ToUpper(name[:1]) + strings.ReplaceAll(name[1:], "_", " "))
		for range 10 + r.IntN(31) {
			desc.WriteByte(' ')
			desc.WriteString(words[r.IntN(len(words))])
		}
		desc.WriteByte('.')
		props := map[string]any{}
		var order []string
		for range 1 + r.IntN(6) {
			kind := argKinds[r.IntN(len(argKinds))]
			names := argNames[kind]
			arg := names[r.IntN(len(names))]
			if _, taken := props[arg]; taken {
				continue
			}
			props[arg] = argSchema(kind, r)
			order = append(order, arg)
		}
		required := []any{order[0]}
		if len(order) > 2 && r.IntN(2) == 0 {
			required = append(required, order[1])
		}
		out[i] = Tool{Name: name, Description: desc.String(), InputSchema: map[string]any{
			"type": "object", "properties": props, "required": required, "additionalProperties": false}}
	}
	return out, nil
}

const kindTool uint64 = 0x70

func argSchema(kind string, r *rand.Rand) map[string]any {
	switch kind {
	case "string":
		return map[string]any{"type": "string", "minLength": 1, "maxLength": 64 << r.IntN(5)}
	case "id":
		return map[string]any{"type": "string", "pattern": "^[a-z0-9-]{1,36}$"}
	case "integer":
		lo := r.IntN(2)
		return map[string]any{"type": "integer", "minimum": lo, "maximum": lo + 10*(1+r.IntN(100))}
	case "boolean":
		return map[string]any{"type": "boolean"}
	case "enum":
		k := 2 + r.IntN(4)
		start := r.IntN(len(enumValues) - k + 1)
		vals := make([]any, k)
		for i := range vals {
			vals[i] = enumValues[start+i]
		}
		return map[string]any{"type": "string", "enum": vals}
	default: // array
		return map[string]any{"type": "array", "maxItems": 4 + r.IntN(13),
			"items": map[string]any{"type": "string", "minLength": 1, "maxLength": 32}}
	}
}

// Calls returns n calls of the catalog's tools, popular tools more often
// (Zipf over the catalog order), each with every required argument and
// about half the optional ones, every value valid for the tool's schema.
func Calls(tools []Tool, n int, seed uint64) ([]Call, error) {
	if len(tools) == 0 || n < 1 {
		return nil, fmt.Errorf("calls: want a catalog and at least one call")
	}
	pcg := rand.NewPCG(0, 0)
	r := rand.New(pcg)
	var pick func() int
	if len(tools) == 1 {
		pick = func() int { return 0 }
	} else {
		z := rand.NewZipf(r, 1.2, 4, uint64(len(tools)-1))
		pick = func() int { return int(z.Uint64()) }
	}
	out := make([]Call, n)
	for i := range out {
		pcg.Seed(seed, kindTool<<56^1<<48^uint64(i))
		t := tools[pick()]
		props, _ := t.InputSchema["properties"].(map[string]any)
		required := map[string]bool{}
		if req, ok := t.InputSchema["required"].([]any); ok {
			for _, x := range req {
				if s, ok := x.(string); ok {
					required[s] = true
				}
			}
		}
		args := map[string]any{}
		for _, name := range slices.Sorted(maps.Keys(props)) {
			if !required[name] && r.IntN(2) == 0 {
				continue
			}
			v, err := argValue(props[name], r)
			if err != nil {
				return nil, fmt.Errorf("tool %s argument %s: %w", t.Name, name, err)
			}
			args[name] = v
		}
		out[i] = Call{Name: t.Name, Arguments: args}
	}
	return out, nil
}

const idAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"

// argValue draws a value valid for one of argSchema's schemas.
func argValue(schema any, r *rand.Rand) (any, error) {
	s, ok := schema.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema is %T, not an object", schema)
	}
	word := func(maxLen int) string {
		var b strings.Builder
		for b.Len() == 0 || r.IntN(3) > 0 {
			w := words[r.IntN(len(words))]
			if b.Len()+len(w)+1 > maxLen {
				break
			}
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(w)
		}
		if b.Len() == 0 {
			b.WriteByte('x')
		}
		return b.String()
	}
	switch s["type"] {
	case "boolean":
		return r.IntN(2) == 0, nil
	case "integer":
		lo, hi := s["minimum"].(int), s["maximum"].(int)
		return lo + r.IntN(hi-lo+1), nil
	case "array":
		items := make([]any, r.IntN(s["maxItems"].(int)+1))
		for i := range items {
			items[i] = word(32)
		}
		return items, nil
	case "string":
		if vals, ok := s["enum"].([]any); ok {
			return vals[r.IntN(len(vals))], nil
		}
		if _, ok := s["pattern"]; ok {
			b := make([]byte, 8+r.IntN(29))
			for i := range b {
				b[i] = idAlphabet[r.IntN(len(idAlphabet))]
			}
			return string(b), nil
		}
		return word(s["maxLength"].(int)), nil
	}
	return nil, fmt.Errorf("schema type %v", s["type"])
}
