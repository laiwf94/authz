package policy

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// App is an app's whole access policy: the app-wide rule that applies
// where no path rule matches, paths anyone may open, and per-path,
// per-method rules.
//
// A request is decided by the most specific rule that matches both its
// path and its method:
//
//  1. the rule that matches more path segments wins;
//  2. at the same depth an exact rule beats a prefix rule;
//  3. at the first segment where two patterns differ, a literal segment
//     beats a {parameter};
//  4. a rule that lists the request's method beats one that lists no
//     methods (every method).
//
// A rule that does not list the request's method does not match at all, so
// a shorter rule (or the app-wide rule) decides instead. Two rules that
// would tie on all four are refused when the policy is compiled.
type App struct {
	Rule              // Providers and the app-wide allow
	Public []string   // path prefixes anyone may open, signed in or not
	Paths  []PathRule // per-path rules
}

// PathRule decides the requests under one path pattern.
//
// Path is a pattern of '/'-separated segments, each a literal or a
// {parameter} matching any one segment. Without Exact it matches the path
// and everything below it at a segment boundary: "/docs" matches "/docs"
// and "/docs/a/b" but not "/docsx". A trailing '/' changes nothing. With
// Exact it matches that path only.
//
// Methods limits the rule to those HTTP methods; empty means every method.
// GET also covers HEAD.
//
// Public lets anyone through, signed in or not; Deny lets nobody through;
// otherwise AnyUser, Emails, EmailDomains and Groups say who may, from the
// app's providers, exactly as the app-wide rule does. Check makes it a
// relationship rule: the authorization engine decides (see CheckRule),
// for every user of the app's providers or, when the rule also lists who
// may, for those it lists.
type PathRule struct {
	Path    string
	Exact   bool
	Methods []string
	Public  bool
	Deny    bool
	Check   *CheckRule

	AnyUser      bool
	Emails       []string
	EmailDomains []string
	Groups       []string
}

// MaxParams is the most {parameter} segments one pattern may have.
const MaxParams = 8

// Reason codes Evaluate adds to those of Compiled.Evaluate.
const (
	AllowedPublic = "public_path"
	DeniedRule    = "denied_by_rule"
	DeniedBadPath = "bad_path"
)

// Policy is an App compiled for matching: the path rules in a segment
// trie, each with its allow rule compiled.
type Policy struct {
	app   *Compiled
	rules []rule
	root  *node // nil when the app has no path rules
}

type rule struct {
	name    string // where the rule came from: "paths[3]" or "public[0]"
	pattern string // the normalized pattern, for explanations
	params  []string
	methods uint16 // methodAny for every method
	exact   bool
	public  bool
	deny    bool
	allow   *Compiled
	check   *compiledCheck // nil unless a relationship rule
}

type node struct {
	lit    map[string]*node
	param  *node
	prefix []int // rule indices, method-specific rules first
	exact  []int
}

// Methods a rule can list. Others are refused at compile time; a request
// with any other method matches only rules that list no methods.
var methodBits = [...]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"}

const methodAny uint16 = 0

func methodBit(m string) uint16 {
	switch m {
	case "GET":
		return 1 << 0
	case "HEAD":
		return 1 << 1
	case "POST":
		return 1 << 2
	case "PUT":
		return 1 << 3
	case "PATCH":
		return 1 << 4
	case "DELETE":
		return 1 << 5
	case "OPTIONS":
		return 1 << 6
	case "CONNECT":
		return 1 << 7
	case "TRACE":
		return 1 << 8
	}
	return 0
}

// RuleError is a problem with one rule of an App. CompileApp joins them
// with errors.Join.
type RuleError struct {
	Rule string // "paths[2]" or "public[0]"
	Msg  string
}

func (e *RuleError) Error() string { return e.Rule + ": " + e.Msg }

// CompileApp checks and compiles an app policy. Every problem is reported,
// joined, each naming the rule ("paths[2]" or "public[0]").
func CompileApp(a App) (*Policy, error) {
	p := &Policy{app: Compile(a.Rule)}
	var errs []error
	add := func(name string, pr PathRule) {
		r, segs, err := compileRule(name, pr, a.Providers)
		if err != nil {
			errs = append(errs, err)
			return
		}
		if p.root == nil {
			p.root = &node{}
		}
		n := p.root
		for _, s := range segs {
			if s == "" { // a {parameter}
				if n.param == nil {
					n.param = &node{}
				}
				n = n.param
				continue
			}
			if n.lit == nil {
				n.lit = map[string]*node{}
			}
			next := n.lit[s]
			if next == nil {
				next = &node{}
				n.lit[s] = next
			}
			n = next
		}
		list := &n.prefix
		if r.exact {
			list = &n.exact
		}
		for _, j := range *list {
			o := p.rules[j]
			if o.methods == r.methods || (o.methods&r.methods) != 0 {
				errs = append(errs, &RuleError{Rule: name, Msg: fmt.Sprintf("pattern %q overlaps %s (%q) for the same methods", r.pattern, o.name, o.pattern)})
				return
			}
		}
		i := len(p.rules)
		p.rules = append(p.rules, r)
		// Method-specific rules are tried before every-method rules.
		if r.methods == methodAny {
			*list = append(*list, i)
		} else {
			*list = append([]int{i}, *list...)
		}
	}
	for i, pr := range a.Paths {
		add(fmt.Sprintf("paths[%d]", i), pr)
	}
	for i, pub := range a.Public {
		add(fmt.Sprintf("public[%d]", i), PathRule{Path: pub, Public: true})
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return p, nil
}

// compileRule checks one rule and splits its pattern into segments, with
// "" standing for a {parameter}.
func compileRule(name string, pr PathRule, providers []string) (rule, []string, error) {
	fail := func(format string, args ...any) (rule, []string, error) {
		return rule{}, nil, &RuleError{Rule: name, Msg: fmt.Sprintf(format, args...)}
	}
	r := rule{name: name, exact: pr.Exact, public: pr.Public, deny: pr.Deny}
	if pr.Public && pr.Deny {
		return fail("a rule cannot be both public and deny")
	}
	who := pr.AnyUser || len(pr.Emails)+len(pr.EmailDomains)+len(pr.Groups) > 0
	if (pr.Public || pr.Deny) && who {
		return fail("a public or deny rule takes no allow (any_user, emails, email_domains or groups)")
	}
	if (pr.Public || pr.Deny) && pr.Check != nil {
		return fail("a public or deny rule takes no check")
	}
	for _, m := range pr.Methods {
		b := methodBit(m)
		if b == 0 {
			return fail("unknown method %q: use one of %s", m, strings.Join(methodBits[:], ", "))
		}
		if r.methods&b != 0 {
			return fail("method %q is listed twice", m)
		}
		r.methods |= b
		if b == methodBit("GET") {
			r.methods |= methodBit("HEAD")
		}
	}
	p := pr.Path
	if p == "" || p[0] != '/' {
		return fail("path %q must start with '/'", p)
	}
	if strings.ContainsAny(p, "%\\?#*;") {
		return fail("path %q may not contain '%%', '\\', '?', '#', '*' or ';'", p)
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] >= 0x7f {
			return fail("path %q may only contain visible ASCII", p)
		}
	}
	trimmed := strings.TrimSuffix(p[1:], "/")
	var segs []string
	if trimmed != "" {
		segs = strings.Split(trimmed, "/")
	}
	seen := map[string]bool{}
	var b strings.Builder
	for _, s := range segs {
		b.WriteByte('/')
		b.WriteString(s)
		switch {
		case s == "" || s == "." || s == "..":
			return fail("path %q has an empty, '.' or '..' segment", p)
		case s[0] == '{':
			pn := s[1 : len(s)-1]
			if s[len(s)-1] != '}' || !paramName(pn) {
				return fail("segment %q of %q: a parameter is a whole segment {name}, the name lower-case letters, digits and '_'", s, p)
			}
			if seen[pn] {
				return fail("parameter {%s} appears twice in %q", pn, p)
			}
			seen[pn] = true
			r.params = append(r.params, pn)
		case strings.ContainsAny(s, "{}"):
			return fail("segment %q of %q: a parameter is a whole segment {name}", s, p)
		}
	}
	if len(r.params) > MaxParams {
		return fail("path %q has more than %d parameters", p, MaxParams)
	}
	if b.Len() == 0 {
		b.WriteByte('/')
	}
	r.pattern = b.String()
	if !pr.Public && !pr.Deny {
		// A relationship rule that lists nobody asks the engine for every
		// user of the app's providers.
		anyUser := pr.AnyUser || (pr.Check != nil && !who)
		r.allow = Compile(Rule{Providers: providers, AnyUser: anyUser, Emails: pr.Emails,
			EmailDomains: pr.EmailDomains, Groups: pr.Groups})
	}
	if pr.Check != nil {
		cc, err := compileCheck(pr.Check, r.params)
		if err != nil {
			return fail("%v", err)
		}
		r.check = cc
	}
	// The trie stores parameters as "".
	for i, s := range segs {
		if s[0] == '{' {
			segs[i] = ""
		}
	}
	return r, segs, nil
}

func paramName(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// Match is the rule a request matched.
type Match struct {
	// Rule is the index of the matched path rule (see Policy.RuleName),
	// or -1 when the app-wide rule applies or the path is bad.
	Rule int
	// Bad says the path could not be read unambiguously (an encoded '/',
	// '\' or NUL, a ';', an invalid escape or no path at all); it is
	// denied whoever asks.
	Bad bool
	// Public says the request needs no sign-in.
	Public bool
	// Path is the path the rules were matched against: decoded, with
	// "." and ".." segments and repeated slashes resolved.
	Path string
	// Params holds the values of the matched pattern's parameters, in
	// pattern order; NParams says how many there are.
	Params  [MaxParams]string
	NParams int
}

// Param returns the value of the named parameter of the matched pattern.
func (p *Policy) Param(m *Match, name string) (string, bool) {
	if m.Rule < 0 {
		return "", false
	}
	for i, n := range p.rules[m.Rule].params {
		if n == name && i < m.NParams {
			return m.Params[i], true
		}
	}
	return "", false
}

// RuleName names a matched rule as the configuration does: "paths[3]",
// "public[0]", or "allow" for the app-wide rule.
func (p *Policy) RuleName(i int) string {
	if i < 0 || i >= len(p.rules) {
		return "allow"
	}
	return p.rules[i].name
}

// RulePattern returns a rule's normalized pattern, or "" for the
// app-wide rule.
func (p *Policy) RulePattern(i int) string {
	if i < 0 || i >= len(p.rules) {
		return ""
	}
	return p.rules[i].pattern
}

// HasPathRules says whether the policy looks at paths at all.
func (p *Policy) HasPathRules() bool { return p.root != nil }

// Match finds the rule for a request. method is the HTTP method; rawPath
// is the request path as sent, percent-encoded, without the query. An app
// without path rules does not look at either, so its decisions are those
// of the app-wide rule for every request.
func (p *Policy) Match(method, rawPath string) Match {
	m := Match{Rule: -1}
	if p.root == nil {
		return m
	}
	clean, ok := cleanPath(rawPath)
	if !ok {
		m.Bad = true
		return m
	}
	m.Path = clean
	w := walker{p: p, method: methodBit(method), best: -1}
	w.walk(p.root, clean, 0, 0)
	if w.best >= 0 {
		m.Rule = w.best
		m.Public = p.rules[w.best].public
		m.NParams = w.bestN
		m.Params = w.bestParams
	}
	return m
}

// Evaluate decides a matched request for an identity; id is nil when the
// request carries no session. It returns whether the request may proceed
// and a reason code. A relationship rule cannot be decided here: when the
// identity passes the rule's other conditions Evaluate answers false with
// CheckRequired, and Authorize asks the engine.
func (p *Policy) Evaluate(m *Match, id *Identity) (bool, string) {
	if m.Bad {
		return false, DeniedBadPath
	}
	c := p.app
	if m.Rule >= 0 {
		r := &p.rules[m.Rule]
		switch {
		case r.public:
			return true, AllowedPublic
		case r.deny:
			return false, DeniedRule
		}
		c = r.allow
	}
	if id == nil {
		return false, DeniedNoSubject
	}
	ok, reason := c.Evaluate(*id)
	if ok && m.Rule >= 0 && p.rules[m.Rule].check != nil {
		return false, CheckRequired
	}
	return ok, reason
}

// Decide matches and evaluates in one call. A relationship rule answers
// CheckRequired; see Authorize.
func (p *Policy) Decide(method, rawPath string, id *Identity) (bool, string) {
	m := p.Match(method, rawPath)
	return p.Evaluate(&m, id)
}

type walker struct {
	p      *Policy
	method uint16

	params [MaxParams]string

	best       int
	bestScore  int
	bestN      int
	bestParams [MaxParams]string
}

// walk visits n, which the first depth segments of the path reached, with
// rest the remaining path ("" or "/seg/..."). Literal children are visited
// before the parameter child, and a candidate replaces the best only when
// it scores strictly higher, so ties go to literals (order rule 3).
func (w *walker) walk(n *node, rest string, depth, np int) {
	end := rest == "" || rest == "/"
	if end {
		w.offer(n.exact, 2*depth+1, np)
	}
	w.offer(n.prefix, 2*depth, np)
	if end {
		return
	}
	rest = rest[1:]
	seg, after := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		seg, after = rest[:i], rest[i:]
	}
	if c := n.lit[seg]; c != nil {
		w.walk(c, after, depth+1, np)
	}
	if n.param != nil && seg != "" && np < MaxParams {
		w.params[np] = seg
		w.walk(n.param, after, depth+1, np+1)
	}
}

// offer considers the rules at one node, method-specific first.
func (w *walker) offer(list []int, score, np int) {
	if score <= w.bestScore && w.best >= 0 {
		return
	}
	for _, i := range list {
		r := &w.p.rules[i]
		if r.methods == methodAny || r.methods&w.method != 0 {
			w.best, w.bestScore, w.bestN = i, score, np
			w.bestParams = w.params
			return
		}
	}
}

// cleanPath decodes a raw request path and resolves "." and ".." segments
// and repeated slashes, the way the upstream will see it. It refuses what
// two servers could read differently: an encoded '/' or '\', a '\', a ';'
// (path parameters, which some servers drop and some keep), NUL or other
// control bytes, and invalid escapes. A path that needs no change is
// returned without allocating.
func cleanPath(raw string) (string, bool) {
	if raw == "" || raw[0] != '/' {
		return "", false
	}
	escaped := false
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '%':
			escaped = true
		case c == '\\' || c == ';' || c < 0x20 || c == 0x7f:
			return "", false
		}
	}
	p := raw
	if escaped {
		var b strings.Builder
		b.Grow(len(raw))
		for i := 0; i < len(raw); i++ {
			c := raw[i]
			if c != '%' {
				b.WriteByte(c)
				continue
			}
			if i+2 >= len(raw) {
				return "", false
			}
			h, l := unhex(raw[i+1]), unhex(raw[i+2])
			if h < 0 || l < 0 {
				return "", false
			}
			d := byte(h<<4 | l)
			if d == '/' || d == '\\' || d == ';' || d < 0x20 || d == 0x7f {
				return "", false
			}
			b.WriteByte(d)
			i += 2
		}
		p = b.String()
	}
	if needsClean(p) {
		p = path.Clean(p)
	}
	return p, true
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

// needsClean reports a repeated '/' or a "." or ".." segment.
func needsClean(p string) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != '/' {
			continue
		}
		rest := p[i+1:]
		switch {
		case strings.HasPrefix(rest, "/"),
			rest == ".", strings.HasPrefix(rest, "./"),
			rest == "..", strings.HasPrefix(rest, "../"):
			return true
		}
	}
	return false
}
