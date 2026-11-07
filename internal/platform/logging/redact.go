package logging

import (
	"encoding"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"sync"
)

// Redacted is what a secret value is written as.
const Redacted = "[REDACTED]"

// Secret is a string that is never written out: a Handler, fmt and
// encoding/json all print it as Redacted. Wrap keys, tokens and passwords
// in it before they reach a logger, an error or a payload that may be
// logged.
type Secret string

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// String implements fmt.Stringer.
func (Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer, so %#v does not print the value.
func (Secret) GoString() string { return Redacted }

// MarshalText implements encoding.TextMarshaler, which encoding/json uses.
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// Reveal returns the secret's value, for the one place that needs it.
func (s Secret) Reveal() string { return string(s) }

// DefaultSecretKeys are attribute keys whose values a Handler always
// redacts, compared after lowercasing and turning "-" into "_". Any key
// ending in "_token", "_secret", "_password", "_passwd", "_api_key",
// "_apikey" or "_private_key" is redacted too.
var DefaultSecretKeys = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"authorization", "proxy_authorization", "cookie", "set_cookie",
	"private_key", "client_secret", "access_token", "refresh_token", "id_token",
	"assertion", "samlresponse", "code_verifier",
}

// secretSuffixes are matched from the last "_" or, for the two-word ones,
// the one before it.
var secretSuffixes = map[string]bool{
	"_token": true, "_secret": true, "_password": true, "_passwd": true,
	"_apikey": true, "_api_key": true, "_private_key": true,
}

// normKey lowercases k and turns "-" into "_", allocating only when k needs
// a change.
func normKey(k string) string {
	for i := 0; i < len(k); i++ {
		if c := k[i]; c == '-' || ('A' <= c && c <= 'Z') {
			return strings.ReplaceAll(strings.ToLower(k), "-", "_")
		}
	}
	return k
}

// redactor holds a Handler's secret keys.
type redactor struct {
	keys map[string]bool
}

func newRedactor(extra []string) *redactor {
	r := &redactor{keys: make(map[string]bool, len(DefaultSecretKeys)+len(extra))}
	for _, k := range DefaultSecretKeys {
		r.keys[k] = true
	}
	for _, k := range extra {
		r.keys[normKey(k)] = true
	}
	return r
}

func (r *redactor) secretKey(k string) bool {
	n := normKey(k)
	if r.keys[n] {
		return true
	}
	i := strings.LastIndexByte(n, '_')
	if i <= 0 {
		return false
	}
	if secretSuffixes[n[i:]] {
		return true
	}
	j := strings.LastIndexByte(n[:i], '_')
	return j > 0 && secretSuffixes[n[j:]]
}

// replace is the ReplaceAttr step that redacts. It is called for every
// attribute that is not a group, at any depth, after LogValuers resolve.
func (r *redactor) replace(_ []string, a slog.Attr) slog.Attr {
	if r.secretKey(a.Key) {
		if a.Value.Kind() == slog.KindString && a.Value.String() == "" {
			return a // an empty value says it is unset, which is not secret
		}
		return slog.String(a.Key, Redacted)
	}
	if a.Value.Kind() == slog.KindAny {
		if v, ok := redactValue(a.Value.Any()); ok {
			a.Value = v
		}
	}
	return a
}

// redactValue turns a struct with fields tagged `log:"secret"`, directly or
// in nested structs, into a group with those fields redacted, so the JSON
// encoder never sees them. A slice, array or map of such values is written
// as Redacted whole. It reports false for anything else, which is left
// alone, and for types that render themselves (error, json.Marshaler,
// encoding.TextMarshaler), whose author decides what they print.
func redactValue(x any) (slog.Value, bool) {
	if x == nil {
		return slog.Value{}, false
	}
	switch x.(type) {
	case error, json.Marshaler, encoding.TextMarshaler, slog.LogValuer:
		return slog.Value{}, false
	}
	v := reflect.ValueOf(x)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return slog.Value{}, false
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Struct:
		info := typeInfoOf(v.Type())
		if !info.secret {
			return slog.Value{}, false
		}
		attrs := make([]slog.Attr, 0, len(info.fields))
		for _, f := range info.fields {
			fv, ok := fieldByIndex(v, f.index)
			if !ok || (f.omitEmpty && fv.IsZero()) {
				continue
			}
			if f.secret {
				attrs = append(attrs, slog.String(f.name, Redacted))
				continue
			}
			attrs = append(attrs, slog.Any(f.name, fv.Interface()))
		}
		return slog.GroupValue(attrs...), true
	case reflect.Slice, reflect.Array, reflect.Map:
		if containsSecret(v.Type()) {
			return slog.StringValue(Redacted), true
		}
	}
	return slog.Value{}, false
}

// fieldByIndex follows index through embedded pointers, reporting false at
// a nil one, as encoding/json leaves those fields out.
func fieldByIndex(v reflect.Value, index []int) (reflect.Value, bool) {
	for i, x := range index {
		if i > 0 {
			for v.Kind() == reflect.Pointer {
				if v.IsNil() {
					return reflect.Value{}, false
				}
				v = v.Elem()
			}
		}
		v = v.Field(x)
	}
	return v, true
}

type field struct {
	name      string
	index     []int
	secret    bool
	omitEmpty bool
}

type typeInfo struct {
	fields []field
	secret bool // a field, or something inside one, is tagged secret
}

var typeInfos sync.Map // reflect.Type -> *typeInfo

func typeInfoOf(t reflect.Type) *typeInfo {
	if ti, ok := typeInfos.Load(t); ok {
		return ti.(*typeInfo)
	}
	ti := &typeInfo{}
	collectFields(t, nil, ti, map[reflect.Type]bool{t: true})
	ti.fields = dominant(ti.fields)
	ti.secret = containsSecret(t)
	actual, _ := typeInfos.LoadOrStore(t, ti)
	return actual.(*typeInfo)
}

// collectFields lists t's fields the way encoding/json names them: the json
// tag's name if there is one, exported fields only, "-" skipped and
// untagged embedded structs flattened.
func collectFields(t reflect.Type, prefix []int, ti *typeInfo, seen map[reflect.Type]bool) {
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		tag := sf.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		index := append(append([]int(nil), prefix...), i)
		if sf.Anonymous && name == "" {
			et := sf.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct && !seen[et] {
				seen[et] = true
				collectFields(et, index, ti, seen)
				delete(seen, et)
				continue
			}
		}
		if !sf.IsExported() {
			continue
		}
		if name == "" {
			name = sf.Name
		}
		ti.fields = append(ti.fields, field{
			name:      name,
			index:     index,
			secret:    isSecretTag(sf.Tag.Get("log")),
			omitEmpty: strings.Contains(","+opts+",", ",omitempty,"),
		})
	}
}

// dominant resolves name clashes as encoding/json does for untagged
// fields: the shallowest field wins, and of several at that depth the first
// one (encoding/json would drop them all; writing one is the safer choice
// for a log line, and its secret tag still applies).
func dominant(fields []field) []field {
	out := fields[:0:0]
	pos := map[string]int{}
	for _, f := range fields {
		i, ok := pos[f.name]
		if !ok {
			pos[f.name] = len(out)
			out = append(out, f)
			continue
		}
		if len(f.index) < len(out[i].index) {
			out[i] = f
		}
	}
	return out
}

func isSecretTag(tag string) bool {
	for _, p := range strings.Split(tag, ",") {
		if strings.TrimSpace(p) == "secret" {
			return true
		}
	}
	return false
}

var containsMemo sync.Map // reflect.Type -> bool

// containsSecret reports whether a value of type t can hold a field tagged
// secret, through pointers, structs, slices, arrays and maps.
func containsSecret(t reflect.Type) bool {
	if v, ok := containsMemo.Load(t); ok {
		return v.(bool)
	}
	r := containsSecretIn(t, map[reflect.Type]bool{})
	containsMemo.Store(t, r)
	return r
}

func containsSecretIn(t reflect.Type, visiting map[reflect.Type]bool) bool {
	if visiting[t] {
		return false
	}
	visiting[t] = true
	defer delete(visiting, t)
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return containsSecretIn(t.Elem(), visiting)
	case reflect.Map:
		return containsSecretIn(t.Key(), visiting) || containsSecretIn(t.Elem(), visiting)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			sf := t.Field(i)
			if sf.Tag.Get("json") == "-" || (!sf.IsExported() && !sf.Anonymous) {
				continue
			}
			if isSecretTag(sf.Tag.Get("log")) || containsSecretIn(sf.Type, visiting) {
				return true
			}
		}
	}
	return false
}
