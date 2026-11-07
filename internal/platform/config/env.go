package config

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// EnvPrefix starts every environment override. A member of a section is
// overridden by EnvPrefix, the section name and the member's path, upper
// case and joined by '_': $.serve.addr is AUTHZ_SERVE_ADDR and
// $.gateway.session.idle_timeout is AUTHZ_GATEWAY_SESSION_IDLE_TIMEOUT.
// Members inside arrays and maps have no variable.
const EnvPrefix = "AUTHZ_"

// SecretFileSuffix is added to a Secret's variable to name a file holding
// it: AUTHZ_SERVE_API_KEYS_FILE=/run/secrets/api-keys.
const SecretFileSuffix = "_FILE"

// binding is one environment variable that overrides one member.
type binding struct {
	name  string // AUTHZ_SERVE_ADDR
	index []int  // field indexes from the section struct
	rel   []string
	file  bool // the _FILE spelling of a Secret
}

// bindings lists the variables of section type t, sorted by name.
func bindings(prefix string, t reflect.Type) []binding {
	var out []binding
	var walk func(t reflect.Type, index []int, rel []string)
	walk = func(t reflect.Type, index []int, rel []string) {
		for name, f := range fields(t) {
			idx := append(append([]int(nil), index...), f.Index...)
			r := append(append([]string(nil), rel...), name)
			env := prefix + strings.ToUpper(strings.Join(r, "_"))
			switch {
			case f.Type == secretType:
				out = append(out, binding{name: env, index: idx, rel: r},
					binding{name: env + SecretFileSuffix, index: idx, rel: r, file: true})
			case f.Type == durationType || f.Type.Kind() == reflect.String || f.Type.Kind() == reflect.Bool ||
				f.Type.Kind() == reflect.Int || f.Type.Kind() == reflect.Int64 || f.Type.Kind() == reflect.Int32:
				out = append(out, binding{name: env, index: idx, rel: r})
			case f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.String && f.Type.Elem() != durationType:
				out = append(out, binding{name: env, index: idx, rel: r})
			case f.Type.Kind() == reflect.Struct:
				walk(f.Type, idx, r)
			}
		}
	}
	walk(t, nil, nil)
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func (b binding) path(section string) string {
	p := KeyPath("$", section)
	for _, r := range b.rel {
		p = KeyPath(p, r)
	}
	return p
}

// applyEnv sets the members of section value v (a pointer to the section's
// struct) that env overrides, recording each overridden path. It reports
// whether any variable was set.
func applyEnv(s *section, v reflect.Value, env map[string]string, r *report) bool {
	any := false
	for _, b := range s.env {
		val, ok := env[b.name]
		if !ok || val == "" {
			continue
		}
		any = true
		path := b.path(s.name)
		f := v.Elem().FieldByIndex(b.index)
		if f.Type() == secretType {
			base := strings.TrimSuffix(b.name, SecretFileSuffix)
			if env[base] != "" && env[base+SecretFileSuffix] != "" {
				if !b.file { // report the pair once
					r.fromEnv[path] = base
					r.errorf(path, "set by both %s and %s; unset one", base, base+SecretFileSuffix)
				}
				continue
			}
			r.fromEnv[path] = b.name
			if b.file {
				f.Set(reflect.ValueOf(Secret{File: val}))
			} else {
				f.Set(reflect.ValueOf(Secret{value: strings.TrimSpace(val), direct: true}))
			}
			continue
		}
		r.fromEnv[path] = b.name
		switch {
		case f.Type() == durationType:
			d, err := parseDuration(val)
			if err != nil {
				r.errorf(path, "%v", err)
				continue
			}
			f.SetInt(int64(d))
		case f.Kind() == reflect.String:
			f.SetString(val)
		case f.Kind() == reflect.Bool:
			bv, err := strconv.ParseBool(val)
			if err != nil {
				r.errorf(path, "%q is not true or false", val)
				continue
			}
			f.SetBool(bv)
		case f.Kind() == reflect.Slice:
			var list []string
			for _, e := range strings.Split(val, ",") {
				if e = strings.TrimSpace(e); e != "" {
					list = append(list, e)
				}
			}
			f.Set(reflect.ValueOf(list).Convert(f.Type()))
		default: // integers
			n, err := strconv.ParseInt(strings.TrimSpace(val), 10, f.Type().Bits())
			if err != nil {
				r.errorf(path, "%q is not a whole number between %d and %d", val, minInt(f.Type()), maxInt(f.Type()))
				continue
			}
			f.SetInt(n)
		}
	}
	return any
}

// unknownEnv warns about variables under a section's prefix that override
// nothing, which are almost always misspelt.
func unknownEnv(s *section, env map[string]string, r *report) {
	known := make([]string, len(s.env))
	for i, b := range s.env {
		known[i] = b.name
	}
	isKnown := make(map[string]bool, len(known))
	for _, k := range known {
		isKnown[k] = true
	}
	var unknown []string
	for name := range env {
		if strings.HasPrefix(name, s.envPrefix) && !isKnown[name] {
			unknown = append(unknown, name)
		}
	}
	sort.Strings(unknown)
	for _, name := range unknown {
		r.mu.Lock()
		r.problems = append(r.problems, Problem{Path: KeyPath("$", s.name), Env: name, Severity: SeverityWarning,
			Message: "unknown variable" + suggest(name, known)})
		r.mu.Unlock()
	}
}
