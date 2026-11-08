package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

var (
	durationType = reflect.TypeFor[Duration]()
	secretType   = reflect.TypeFor[Secret]()
	// skipType marks a Skip section: its value is read past, not decoded.
	skipType = reflect.TypeFor[struct{ skip struct{} }]()
)

// checkType reports a type the walker has no rule for. Schemas are checked
// when they are built, so a bad section type fails at start-up of every
// test rather than on some document.
func checkType(t reflect.Type, where string) error {
	switch {
	case t == durationType || t == secretType:
		return nil
	case t.Kind() == reflect.String || t.Kind() == reflect.Bool:
		return nil
	case t.Kind() == reflect.Int || t.Kind() == reflect.Int64 || t.Kind() == reflect.Int32:
		return nil
	case t.Kind() == reflect.Float64:
		return nil
	case t.Kind() == reflect.Slice:
		return checkType(t.Elem(), where+"[]")
	case t.Kind() == reflect.Map:
		if t.Key().Kind() != reflect.String {
			return fmt.Errorf("config: %s: map keys must be strings", where)
		}
		return checkType(t.Elem(), where+"{}")
	case t.Kind() == reflect.Struct:
		names := map[string]bool{}
		for i := range t.NumField() {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if !f.IsExported() || name == "-" {
				continue
			}
			if name == "" {
				return fmt.Errorf("config: %s.%s has no json name", where, f.Name)
			}
			if !fieldName.MatchString(name) {
				return fmt.Errorf("config: %s.%s: json name %q must be lower-case letters, digits and '_'", where, f.Name, name)
			}
			if names[name] {
				return fmt.Errorf("config: %s: two fields are named %q", where, name)
			}
			names[name] = true
			if err := checkType(f.Type, where+"."+name); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("config: %s: no rule for %s", where, t)
}

// fields returns the JSON members of struct type t.
func fields(t reflect.Type) map[string]reflect.StructField {
	out := map[string]reflect.StructField{}
	for i := range t.NumField() {
		f := t.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); f.IsExported() && name != "" && name != "-" {
			out[name] = f
		}
	}
	return out
}

// errSyntax aborts the walk; the document cannot be read further.
var errSyntax = errors.New("syntax")

// walker reads the token stream of a document against Go types. It reports
// unknown, duplicate and mistyped members with their paths and returns the
// document with those removed, so the checks can still run over everything
// that was well-formed.
type walker struct {
	dec *json.Decoder
	r   *report
}

func newWalker(r *report) *walker {
	dec := json.NewDecoder(strings.NewReader(string(r.src)))
	dec.UseNumber()
	return &walker{dec: dec, r: r}
}

// start returns the offset of the next value, skipping what the decoder has
// not consumed yet between tokens (white space, ':' and ',').
func (w *walker) start() int {
	off := int(w.dec.InputOffset())
	for off < len(w.r.src) && strings.IndexByte(" \t\r\n:,", w.r.src[off]) >= 0 {
		off++
	}
	return off
}

func (w *walker) token() (json.Token, error) {
	tok, err := w.dec.Token()
	if err != nil {
		return nil, w.syntax(err)
	}
	return tok, nil
}

func (w *walker) syntax(err error) error {
	off := int(w.dec.InputOffset())
	msg := err.Error()
	var se *json.SyntaxError
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(msg, "unexpected end of JSON input") {
		msg = "unexpected end of file"
		off = len(w.r.src)
	} else if errors.As(err, &se) && se.Offset > 0 {
		// Offset counts the bytes read, the bad one included.
		off = int(se.Offset) - 1
	}
	line, col := lineCol(w.r.src, off)
	w.r.mu.Lock()
	w.r.problems = append(w.r.problems, Problem{Path: "$", Line: line, Column: col, Message: "invalid JSON: " + strings.TrimPrefix(msg, "json: ")})
	w.r.mu.Unlock()
	return errSyntax
}

// value reads one value of type t at path. keep is false when the value was
// wrong (or null) and has been dropped from the cleaned document.
func (w *walker) value(t reflect.Type, path string) (v any, keep bool, err error) {
	w.r.pos[path] = w.start()
	tok, err := w.token()
	if err != nil {
		return nil, false, err
	}
	if tok == nil {
		// null leaves the member unset, as if it were absent.
		return nil, false, nil
	}
	if t == skipType {
		if _, ok := tok.(json.Delim); ok {
			return nil, false, w.skipRest()
		}
		return nil, false, nil
	}
	switch {
	case t == durationType:
		str, ok := tok.(string)
		if !ok {
			return w.mismatch(tok, path, `a duration string like "90s" or "8h"`)
		}
		if _, err := parseDuration(str); err != nil {
			w.r.errorf(path, "%v", err)
			return nil, false, nil
		}
		return str, true, nil
	case t == secretType:
		if _, ok := tok.(string); ok {
			w.r.errorf(path, `secrets are not written in the file: use {"file": "/path"} or {"env": "NAME"}`)
			return nil, false, nil
		}
		if tok != json.Delim('{') {
			return w.mismatch(tok, path, `{"file": "/path"} or {"env": "NAME"}`)
		}
		v, keep, err := w.object(t, path)
		if err != nil || !keep {
			return v, keep, err
		}
		m := v.(map[string]any)
		file, _ := m["file"].(string)
		env, _ := m["env"].(string)
		switch {
		case file != "" && env != "":
			w.r.errorf(path, `set "file" or "env", not both`)
			return nil, false, nil
		case file == "" && env == "":
			w.r.errorf(path, `set "file" to a path or "env" to a variable name`)
			return nil, false, nil
		}
		return m, true, nil
	case t.Kind() == reflect.String:
		if str, ok := tok.(string); ok {
			return str, true, nil
		}
		return w.mismatch(tok, path, "a string")
	case t.Kind() == reflect.Bool:
		if b, ok := tok.(bool); ok {
			return b, true, nil
		}
		return w.mismatch(tok, path, "true or false")
	case t.Kind() == reflect.Int || t.Kind() == reflect.Int64 || t.Kind() == reflect.Int32:
		n, ok := tok.(json.Number)
		if !ok {
			return w.mismatch(tok, path, "a whole number")
		}
		i, err := strconv.ParseInt(string(n), 10, t.Bits())
		if err != nil {
			w.r.errorf(path, "%s is not a whole number between %d and %d", n, minInt(t), maxInt(t))
			return nil, false, nil
		}
		return i, true, nil
	case t.Kind() == reflect.Float64:
		n, ok := tok.(json.Number)
		if !ok {
			return w.mismatch(tok, path, "a number")
		}
		f, err := parseFloat(string(n))
		if err != nil {
			w.r.errorf(path, "%v", err)
			return nil, false, nil
		}
		return f, true, nil
	case t.Kind() == reflect.Slice:
		if tok != json.Delim('[') {
			return w.mismatch(tok, path, "an array")
		}
		out := []any{}
		for i := 0; w.dec.More(); i++ {
			ev, ok, err := w.value(t.Elem(), IndexPath(path, i))
			if err != nil {
				return nil, false, err
			}
			if ok {
				out = append(out, ev)
			}
		}
		if _, err := w.token(); err != nil {
			return nil, false, err
		}
		return out, true, nil
	case t.Kind() == reflect.Map:
		if tok != json.Delim('{') {
			return w.mismatch(tok, path, "an object")
		}
		return w.members(path, func(key string) (reflect.Type, bool, []string) { return t.Elem(), true, nil })
	case t.Kind() == reflect.Struct:
		if tok != json.Delim('{') {
			return w.mismatch(tok, path, "an object")
		}
		return w.object(t, path)
	}
	panic("config: no rule for " + t.String()) // checkType refused it
}

func (w *walker) object(t reflect.Type, path string) (any, bool, error) {
	fs := fields(t)
	names := make([]string, 0, len(fs))
	for name := range fs {
		names = append(names, name)
	}
	return w.members(path, func(key string) (reflect.Type, bool, []string) {
		f, ok := fs[key]
		return f.Type, ok, names
	})
}

// members reads the members of an object whose '{' has been read. lookup
// gives each key's type, or false and the known names for a key that does
// not belong.
func (w *walker) members(path string, lookup func(string) (reflect.Type, bool, []string)) (any, bool, error) {
	out := map[string]any{}
	seen := map[string]bool{}
	for w.dec.More() {
		keyOff := w.start()
		tok, err := w.token()
		if err != nil {
			return nil, false, err
		}
		key := tok.(string) // object keys are always strings
		kp := KeyPath(path, key)
		w.r.pos[kp] = keyOff
		ft, known, names := lookup(key)
		switch {
		case seen[key]:
			w.r.errorf(kp, "duplicate member %q", key)
			known = false
		case !known:
			w.r.errorf(kp, "unknown member%s", suggest(key, names))
		}
		seen[key] = true
		if !known {
			if err := w.skip(); err != nil {
				return nil, false, err
			}
			continue
		}
		v, ok, err := w.value(ft, kp)
		if err != nil {
			return nil, false, err
		}
		if ok {
			out[key] = v
		}
	}
	if _, err := w.token(); err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func (w *walker) mismatch(tok json.Token, path, want string) (any, bool, error) {
	got := "a string"
	switch tok.(type) {
	case nil:
		got = "null"
	case json.Delim:
		got = "an object"
		if tok == json.Delim('[') {
			got = "an array"
		}
	case bool:
		got = "a boolean"
	case json.Number:
		got = "a number"
	}
	w.r.errorf(path, "must be %s, not %s", want, got)
	if _, ok := tok.(json.Delim); ok {
		return nil, false, w.skipRest()
	}
	return nil, false, nil
}

// skip consumes one whole value.
func (w *walker) skip() error {
	tok, err := w.token()
	if err != nil {
		return err
	}
	if _, ok := tok.(json.Delim); ok {
		return w.skipRest()
	}
	return nil
}

// skipRest consumes the rest of an array or object whose opening delimiter
// has been read.
func (w *walker) skipRest() error {
	for depth := 1; depth > 0; {
		tok, err := w.token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	return nil
}

// end reports anything after the top-level value.
func (w *walker) end() {
	off := w.start()
	if _, err := w.dec.Token(); !errors.Is(err, io.EOF) {
		line, col := lineCol(w.r.src, off)
		w.r.mu.Lock()
		w.r.problems = append(w.r.problems, Problem{Path: "$", Line: line, Column: col, Message: "trailing data after the JSON object"})
		w.r.mu.Unlock()
	}
}

// suggest names the member the author probably meant: one that differs only
// in case, or is at most two edits away.
func suggest(key string, names []string) string {
	var best []string
	for _, name := range names {
		if strings.EqualFold(name, key) || editDistance(name, key) <= 2 {
			best = append(best, name)
		}
	}
	if len(best) == 0 {
		return ""
	}
	sort.Strings(best)
	return fmt.Sprintf(" (did you mean %q?)", best[0])
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// parseFloat reads a finite number.
func parseFloat(s string) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, fmt.Errorf("%s is not a finite number", s)
	}
	return f, nil
}

func minInt(t reflect.Type) int64 { return -1 << (t.Bits() - 1) }
func maxInt(t reflect.Type) int64 { return 1<<(t.Bits()-1) - 1 }
