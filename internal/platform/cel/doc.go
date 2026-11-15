// Package cel is the platform's one expression language: a subset of the
// Common Expression Language (CEL) for relationship caveats in
// internal/authz and tool policy conditions in internal/agents, with one
// parser, one type checker and one set of limits for both.
//
// An Env declares the variables an expression may use. Compile parses an
// expression and checks it against the Env, returning a Checked that
// records the type of every node, the overloads every call can resolve to,
// and string-literal arguments (patterns, times, durations, zones and
// addresses) already parsed:
//
//	env, err := cel.NewEnv([]cel.Var{
//		{Name: "now", Type: cel.Timestamp},
//		{Name: "client_ip", Type: cel.IPAddress},
//	})
//	c, err := env.CompileAs(`client_ip.in_cidr("10.0.0.0/8") &&
//		now.getHours("Europe/Berlin") < 18`, cel.Bool)
//
// # The subset
//
// Literals: int (decimal or 0x hex), uint (1u), double (1.5, 1e3), string
// (single, double or triple quotes; r"" for raw), true, false and null.
// Bytes literals and message construction are not part of the subset.
//
// Operators, by precedence from lowest: ?:, ||, &&, the relations
// (== != < <= > >= in), + and -, * / and %, the unary ! and -, then member
// access (a.f), calls (a.f(x)) and indexing (a[i]). Equality and ordering
// work across int, uint and double by value. && and || chains are built
// balanced, so long chains stay shallow.
//
// Types: bool, int, uint, double, string, timestamp, duration, ipaddress,
// cidr, list<T>, map<K, V> with bool, int, uint or string keys, and dyn for
// a value whose type is known only when it runs. ParseType reads them as
// schemas write them.
//
// Macros: has(m.f), and on lists and maps (over the keys) all, exists,
// exists_one, filter and map with one or two expressions.
//
// Functions: size; contains, startsWith, endsWith and matches (RE2) on
// strings; the conversions int, uint, double, string, bool, timestamp,
// duration and dyn; on timestamps getFullYear, getMonth, getDayOfYear,
// getDayOfMonth, getDate, getDayOfWeek, getHours, getMinutes, getSeconds and
// getMilliseconds, each with an optional time zone; the same four time
// parts of durations; ip, cidr, isIP and isCIDR; on addresses family,
// isLoopback, isPrivate, isUnspecified and in_cidr; on ranges containsIP,
// containsCIDR, ip, prefixLength and masked.
//
// # Limits
//
// Limits bound the source length, the tree depth and the node count, so
// neither parsing nor checking an expression read from a schema or a policy
// file can exhaust the process. Errors carry line and column.
package cel
