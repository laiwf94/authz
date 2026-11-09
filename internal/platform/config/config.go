// Package config is the platform's one configuration file: a versioned JSON
// document with a section per subcommand, every value overridable from the
// environment, secrets kept out of the file as references to files or
// variables, and live reload.
//
//	{
//	  "version": 1,
//	  "serve":   {"addr": ":8080", "api_keys": {"file": "/run/secrets/api-keys"}},
//	  "gateway": {...},
//	  "mcp":     {...}
//	}
//
// Each subcommand registers its section with NewSection: a Go struct with
// json tags, its defaults and its checks. Check reports every problem in a
// document at once, each with its JSON path and its line and column (or the
// environment variable it came from), so "authz check" can print them all.
// A Watcher reloads the file and the secret files it references when any of
// them changes, and keeps the configuration it has when the new one is
// invalid.
package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Version is the document version this build reads. A document must say
// which version it was written for; a newer one is refused rather than
// half understood.
const Version = 1

// MaxFileBytes bounds the configuration file.
const MaxFileBytes = 1 << 20

var (
	sectionName = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}$`)
	fieldName   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// Section is one subcommand's part of the document, built by NewSection.
type Section struct{ s *section }

type section struct {
	name      string
	typ       reflect.Type
	newValue  func() any // a pointer to a new value holding the defaults
	check     func(v any, c *Checker)
	env       []binding
	envPrefix string
	skip      bool // Skip: present or not, never read
}

// NewSection describes the section called name, decoded into a T. T is a
// struct whose exported members have json names of lower-case letters,
// digits and '_'; members may be strings, booleans, integers, float64s,
// Durations, Secrets, structs, slices and maps with string keys. defaults,
// if not nil, fills in a new T before the file and the environment are
// applied. check, if not nil, validates the result; it runs only when the
// section is present, in the file or through an environment variable.
func NewSection[T any](name string, defaults func(*T), check func(*T, *Checker)) Section {
	s := &section{
		name: name,
		typ:  reflect.TypeFor[T](),
		newValue: func() any {
			v := new(T)
			if defaults != nil {
				defaults(v)
			}
			return v
		},
		check: func(v any, c *Checker) {
			if check != nil {
				check(v.(*T), c)
			}
		},
		envPrefix: EnvPrefix + strings.ToUpper(name) + "_",
	}
	return Section{s}
}

// Skip describes a section that belongs to another subcommand. A document
// may hold it with any content; it is not decoded, checked or overridden
// from the environment, and Has reports it absent. A subcommand that reads
// one section of a shared file lists the others with Skip, so a typo in a
// section name is still caught and another subcommand's problems do not
// stop it.
func Skip(name string) Section {
	return Section{&section{name: name, typ: skipType, skip: true,
		envPrefix: EnvPrefix + strings.ToUpper(name) + "_"}}
}

// Schema is the set of sections a document may hold.
type Schema struct {
	sections map[string]*section
	names    []string // sorted
}

// NewSchema checks the sections and returns their schema. It fails on a
// bad name, a type with no decoding rule, or two members that would share
// an environment variable.
func NewSchema(sections ...Section) (*Schema, error) {
	sc := &Schema{sections: map[string]*section{}}
	for _, sec := range sections {
		s := sec.s
		if s == nil {
			return nil, fmt.Errorf("config: zero Section; build sections with NewSection")
		}
		if !sectionName.MatchString(s.name) || s.name == "version" {
			return nil, fmt.Errorf("config: section name %q must be 1-32 lower-case letters and digits, and not \"version\"", s.name)
		}
		if _, dup := sc.sections[s.name]; dup {
			return nil, fmt.Errorf("config: two sections are named %q", s.name)
		}
		if s.skip {
			sc.sections[s.name] = s
			sc.names = append(sc.names, s.name)
			continue
		}
		if s.typ.Kind() != reflect.Struct {
			return nil, fmt.Errorf("config: section %s: %s is not a struct", s.name, s.typ)
		}
		if err := checkType(s.typ, s.name); err != nil {
			return nil, err
		}
		s.env = bindings(s.envPrefix, s.typ)
		for i := 1; i < len(s.env); i++ {
			if s.env[i].name == s.env[i-1].name {
				return nil, fmt.Errorf("config: section %s: %s would set both $.%s.%s and $.%s.%s", s.name, s.env[i].name,
					s.name, strings.Join(s.env[i-1].rel, "."), s.name, strings.Join(s.env[i].rel, "."))
			}
		}
		sc.sections[s.name] = s
		sc.names = append(sc.names, s.name)
	}
	sort.Strings(sc.names)
	return sc, nil
}

// MustSchema is NewSchema for sections fixed at compile time.
func MustSchema(sections ...Section) *Schema {
	sc, err := NewSchema(sections...)
	if err != nil {
		panic(err)
	}
	return sc
}

// EnvNames lists the environment variables that override members of the
// named section, sorted.
func (sc *Schema) EnvNames(section string) []string {
	s, ok := sc.sections[section]
	if !ok || s.skip {
		return nil
	}
	out := make([]string, len(s.env))
	for i, b := range s.env {
		out[i] = b.name
	}
	return out
}

// Config is a loaded configuration. Its section values are shared by every
// reader of the Config and must not be modified.
type Config struct {
	// Version is the document version, always Version for a loaded
	// Config.
	Version int

	sections map[string]any
	sources  []Source
}

// Source is one file a configuration was read from: the configuration file
// itself, then the secret files it references and the files the section
// checks read with Checker.ReadFile, in the order they were read.
type Source struct {
	Path string
	// Sum is the SHA-256 of the contents read; zero when reading failed.
	Sum [sha256.Size]byte
	// Err is why the file could not be read; empty when it was.
	Err string

	limit int64 // the size the file was read with, for the Watcher
}

// Has reports whether the named section is present.
func (c *Config) Has(name string) bool {
	_, ok := c.sections[name]
	return ok
}

// Sources returns the files the configuration was read from.
func (c *Config) Sources() []Source { return append([]Source(nil), c.sources...) }

// Get returns the named section of c, or nil when it is absent or is not a
// T.
func Get[T any](c *Config, name string) *T {
	if c == nil {
		return nil
	}
	v, _ := c.sections[name].(*T)
	return v
}

// Result is a checked document: the configuration and every problem found
// in it.
type Result struct {
	// Config holds everything that was well-formed, with defaults, overrides
	// and secrets applied. It is nil only when the document is not JSON.
	// A Config with errors must not be used.
	Config   *Config
	Problems Problems
	// Sources lists the files read, the configuration file first.
	Sources []Source
}

// Check decodes and validates a document and returns every problem it
// finds. environ is the process environment as os.Environ returns it; it
// supplies overrides and {"env": ...} secrets. Secret files are read.
func (sc *Schema) Check(src []byte, environ []string) *Result {
	l := &loader{env: envMap(environ)}
	return sc.check(src, l)
}

// Load reads, checks and returns the configuration file at path. The error
// is a Problems when the document has errors.
func (sc *Schema) Load(path string, environ []string) (*Config, error) {
	r, err := sc.LoadResult(path, environ)
	if err != nil {
		return nil, err
	}
	if err := r.Problems.Err(); err != nil {
		return nil, err
	}
	return r.Config, nil
}

// LoadResult reads and checks the configuration file at path, returning
// warnings as well as errors. The error is only for a file that could not
// be read.
func (sc *Schema) LoadResult(path string, environ []string) (*Result, error) {
	l := &loader{env: envMap(environ)}
	return sc.load(path, l)
}

func (sc *Schema) load(path string, l *loader) (*Result, error) {
	src, err := l.read(path, MaxFileBytes)
	if err != nil {
		return &Result{Sources: l.sources}, fmt.Errorf("config: %w", err)
	}
	return sc.check(src, l), nil
}

func (sc *Schema) check(src []byte, l *loader) *Result {
	r := newReport(src)
	w := newWalker(r)
	intType := reflect.TypeFor[int]()
	known := append([]string{"version"}, sc.names...)

	r.pos["$"] = w.start()
	tok, err := w.token()
	if err != nil {
		return &Result{Problems: r.sorted(), Sources: l.sources}
	}
	doc := map[string]any{}
	if tok != json.Delim('{') {
		// Not an object: the mismatch is reported, then the sections are
		// checked as if the document were empty, so missing values and the
		// environment are reported too.
		if _, _, err := w.mismatch(tok, "$", "an object"); err != nil {
			return &Result{Problems: r.sorted(), Sources: l.sources}
		}
	} else {
		v, _, err := w.members("$", func(key string) (reflect.Type, bool, []string) {
			if key == "version" {
				return intType, true, nil
			}
			if s, ok := sc.sections[key]; ok {
				return s.typ, true, nil
			}
			return nil, false, known
		})
		if err != nil {
			return &Result{Problems: r.sorted(), Sources: l.sources}
		}
		doc = v.(map[string]any)
	}
	w.end()

	cfg := &Config{Version: Version, sections: map[string]any{}}
	switch v, ok := doc["version"].(int64); {
	case !ok:
		if _, there := r.pos["$.version"]; !there {
			r.errorf("$", `"version" is required; this build reads version %d`, Version)
		}
	case v > Version:
		r.errorf("$.version", "version %d was written for a newer authz; this build reads version %d", v, Version)
	case v < 1:
		r.errorf("$.version", "version %d does not exist; this build reads version %d", v, Version)
	}

	for _, name := range sc.names {
		s := sc.sections[name]
		if s.skip {
			continue
		}
		v := s.newValue()
		raw, inFile := doc[name]
		if inFile {
			b, err := json.Marshal(raw)
			if err != nil {
				panic("config: re-encoding a decoded section: " + err.Error())
			}
			if err := json.Unmarshal(b, v); err != nil {
				panic("config: decoding a checked section: " + err.Error())
			}
		}
		fromEnv := applyEnv(s, reflect.ValueOf(v), l.env, r)
		unknownEnv(s, l.env, r)
		if !inFile && !fromEnv {
			continue
		}
		path := KeyPath("$", name)
		if !inFile {
			r.unplaced[path] = true
		}
		l.resolve(reflect.ValueOf(v).Elem(), path, r)
		s.check(v, &Checker{Path: path, r: r, l: l})
		cfg.sections[name] = v
	}
	cfg.sources = l.sources
	return &Result{Config: cfg, Problems: r.sorted(), Sources: l.sources}
}

func envMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

// loader reads files and remembers what it read.
type loader struct {
	env map[string]string

	mu      sync.Mutex // section checks may read files concurrently
	sources []Source
}

func (l *loader) read(path string, limit int64) ([]byte, error) {
	b, err := readLimited(path, limit)
	src := Source{Path: path, limit: limit}
	if err != nil {
		src.Err = err.Error()
	} else {
		src.Sum = sha256.Sum256(b)
	}
	l.mu.Lock()
	l.sources = append(l.sources, src)
	l.mu.Unlock()
	return b, err
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: file larger than %d bytes", path, limit)
	}
	return b, nil
}

// resolve reads every Secret reference in v, which is at path.
func (l *loader) resolve(v reflect.Value, path string, r *report) {
	t := v.Type()
	switch {
	case t == secretType:
		s := v.Addr().Interface().(*Secret)
		switch {
		case s.direct:
		case s.Env != "":
			if s.value = strings.TrimSpace(l.env[s.Env]); s.value == "" {
				r.errorf(path, "environment variable %s is empty or unset", s.Env)
			}
		case s.File != "":
			b, err := l.read(s.File, MaxSecretBytes)
			if err != nil {
				r.errorf(path, "%v", err)
			} else if s.value = strings.TrimSpace(string(b)); s.value == "" {
				r.errorf(path, "%s is empty", s.File)
			}
		}
	case t.Kind() == reflect.Struct:
		names := make([]string, 0)
		fs := fields(t)
		for name := range fs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			l.resolve(v.FieldByIndex(fs[name].Index), KeyPath(path, name), r)
		}
	case t.Kind() == reflect.Slice:
		for i := range v.Len() {
			l.resolve(v.Index(i), IndexPath(path, i), r)
		}
	case t.Kind() == reflect.Map:
		if !hasSecret(t.Elem()) {
			return
		}
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		for _, k := range keys {
			e := reflect.New(t.Elem()).Elem()
			e.Set(v.MapIndex(k))
			l.resolve(e, KeyPath(path, k.String()), r)
			v.SetMapIndex(k, e)
		}
	}
}

func hasSecret(t reflect.Type) bool {
	switch {
	case t == secretType:
		return true
	case t.Kind() == reflect.Slice || t.Kind() == reflect.Map:
		return hasSecret(t.Elem())
	case t.Kind() == reflect.Struct:
		for _, f := range fields(t) {
			if hasSecret(f.Type) {
				return true
			}
		}
	}
	return false
}
