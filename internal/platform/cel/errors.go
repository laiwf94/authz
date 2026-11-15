package cel

import (
	"fmt"
	"strings"
)

// Error is one problem in an expression, at a byte offset into its source.
type Error struct {
	Pos int // byte offset of the problem
	// Line and Column locate Pos, both from 1; Column counts characters.
	Line, Column int
	Msg          string
}

func (e *Error) Error() string { return fmt.Sprintf("%d:%d: %s", e.Line, e.Column, e.Msg) }

func errorf(pos int, format string, args ...any) *Error {
	return &Error{Pos: pos, Msg: fmt.Sprintf(format, args...)}
}

// Errors are the problems found in one expression, in source order. Parse
// stops at the first; Check reports up to maxErrors.
type Errors []*Error

func (es Errors) Error() string {
	parts := make([]string, len(es))
	for i, e := range es {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "; ")
}

// maxErrors bounds how many problems Check collects before it stops.
const maxErrors = 10

// locate fills in Line and Column of each error from src.
func locate(src string, es Errors) Errors {
	for _, e := range es {
		pos := min(max(e.Pos, 0), len(src))
		e.Line, e.Column = 1, 1
		for _, r := range src[:pos] {
			if r == '\n' {
				e.Line++
				e.Column = 1
			} else {
				e.Column++
			}
		}
	}
	return es
}
