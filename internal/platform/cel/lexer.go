package cel

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

type tokenKind uint8

const (
	tokEOF tokenKind = iota
	tokIdent
	tokInt    // decimal or hex digits, no sign; the parser converts them
	tokUint   // digits with the u suffix removed
	tokDouble // text as written
	tokString // decoded value
	tokBytes  // recognised only to refuse it with a clear message
	tokTrue
	tokFalse
	tokNull
	tokIn
	tokLParen
	tokRParen
	tokLBracket
	tokRBracket
	tokLBrace
	tokRBrace
	tokDot
	tokComma
	tokColon
	tokQuestion
	tokNot
	tokMinus
	tokPlus
	tokStar
	tokSlash
	tokPercent
	tokLess
	tokLessEq
	tokGreater
	tokGreaterEq
	tokEq
	tokNotEq
	tokAnd
	tokOr
)

var tokenText = [...]string{
	tokEOF:       "end of expression",
	tokIdent:     "identifier",
	tokInt:       "integer",
	tokUint:      "unsigned integer",
	tokDouble:    "number",
	tokString:    "string",
	tokBytes:     "bytes",
	tokTrue:      "'true'",
	tokFalse:     "'false'",
	tokNull:      "'null'",
	tokIn:        "'in'",
	tokLParen:    "'('",
	tokRParen:    "')'",
	tokLBracket:  "'['",
	tokRBracket:  "']'",
	tokLBrace:    "'{'",
	tokRBrace:    "'}'",
	tokDot:       "'.'",
	tokComma:     "','",
	tokColon:     "':'",
	tokQuestion:  "'?'",
	tokNot:       "'!'",
	tokMinus:     "'-'",
	tokPlus:      "'+'",
	tokStar:      "'*'",
	tokSlash:     "'/'",
	tokPercent:   "'%'",
	tokLess:      "'<'",
	tokLessEq:    "'<='",
	tokGreater:   "'>'",
	tokGreaterEq: "'>='",
	tokEq:        "'=='",
	tokNotEq:     "'!='",
	tokAnd:       "'&&'",
	tokOr:        "'||'",
}

type token struct {
	kind tokenKind
	pos  int
	text string // identifier name, number digits or decoded string
}

// reserved are the words CEL keeps for itself. They cannot name variables,
// fields or comprehension variables.
var reserved = map[string]bool{
	"as": true, "break": true, "const": true, "continue": true, "else": true,
	"for": true, "function": true, "if": true, "import": true, "let": true,
	"loop": true, "package": true, "namespace": true, "return": true,
	"var": true, "void": true, "while": true,
}

type lexer struct {
	src string
	i   int
}

// next returns the next token, or an error at the offending offset.
func (l *lexer) next() (token, *Error) {
	if err := l.skipSpace(); err != nil {
		return token{}, err
	}
	start := l.i
	if l.i >= len(l.src) {
		return token{kind: tokEOF, pos: start}, nil
	}
	c := l.src[l.i]
	switch {
	case c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
		for l.i < len(l.src) && isIdentByte(l.src[l.i]) {
			l.i++
		}
		word := l.src[start:l.i]
		if l.i < len(l.src) && (l.src[l.i] == '"' || l.src[l.i] == '\'') {
			switch word {
			case "r", "R":
				return l.str(start, true)
			case "b", "B":
				t, err := l.str(start, false)
				t.kind = tokBytes
				return t, err
			case "br", "bR", "Br", "BR", "rb", "rB", "Rb", "RB":
				t, err := l.str(start, true)
				t.kind = tokBytes
				return t, err
			}
		}
		switch word {
		case "true":
			return token{kind: tokTrue, pos: start}, nil
		case "false":
			return token{kind: tokFalse, pos: start}, nil
		case "null":
			return token{kind: tokNull, pos: start}, nil
		case "in":
			return token{kind: tokIn, pos: start}, nil
		}
		return token{kind: tokIdent, pos: start, text: word}, nil
	case '0' <= c && c <= '9' || c == '.' && l.i+1 < len(l.src) && isDigit(l.src[l.i+1]):
		return l.number(start)
	case c == '"' || c == '\'':
		return l.str(start, false)
	}
	two := ""
	if l.i+1 < len(l.src) {
		two = l.src[l.i : l.i+2]
	}
	switch two {
	case "<=":
		l.i += 2
		return token{kind: tokLessEq, pos: start}, nil
	case ">=":
		l.i += 2
		return token{kind: tokGreaterEq, pos: start}, nil
	case "==":
		l.i += 2
		return token{kind: tokEq, pos: start}, nil
	case "!=":
		l.i += 2
		return token{kind: tokNotEq, pos: start}, nil
	case "&&":
		l.i += 2
		return token{kind: tokAnd, pos: start}, nil
	case "||":
		l.i += 2
		return token{kind: tokOr, pos: start}, nil
	}
	var k tokenKind
	switch c {
	case '(':
		k = tokLParen
	case ')':
		k = tokRParen
	case '[':
		k = tokLBracket
	case ']':
		k = tokRBracket
	case '{':
		k = tokLBrace
	case '}':
		k = tokRBrace
	case '.':
		k = tokDot
	case ',':
		k = tokComma
	case ':':
		k = tokColon
	case '?':
		k = tokQuestion
	case '!':
		k = tokNot
	case '-':
		k = tokMinus
	case '+':
		k = tokPlus
	case '*':
		k = tokStar
	case '/':
		k = tokSlash
	case '%':
		k = tokPercent
	case '<':
		k = tokLess
	case '>':
		k = tokGreater
	default:
		r, _ := utf8.DecodeRuneInString(l.src[l.i:])
		if c == '=' || c == '&' || c == '|' {
			return token{}, errorf(start, "unexpected %q; did you mean %q?", c, strings.Repeat(string(c), 2))
		}
		return token{}, errorf(start, "unexpected character %q", r)
	}
	l.i++
	return token{kind: k, pos: start}, nil
}

func (l *lexer) skipSpace() *Error {
	for l.i < len(l.src) {
		switch l.src[l.i] {
		case ' ', '\t', '\n', '\r', '\f':
			l.i++
		case '/':
			if l.i+1 < len(l.src) && l.src[l.i+1] == '/' {
				for l.i < len(l.src) && l.src[l.i] != '\n' {
					l.i++
				}
				continue
			}
			return nil
		default:
			return nil
		}
	}
	return nil
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// number reads an int (decimal or 0x hex), a uint (with a u suffix) or a
// double (with a fraction or an exponent).
func (l *lexer) number(start int) (token, *Error) {
	s := l.src
	if s[l.i] == '0' && l.i+1 < len(s) && (s[l.i+1] == 'x' || s[l.i+1] == 'X') {
		l.i += 2
		d := l.i
		for l.i < len(s) && isHex(s[l.i]) {
			l.i++
		}
		if l.i == d {
			return token{}, errorf(start, "hexadecimal literal has no digits")
		}
		return l.intSuffix(start, s[start:l.i])
	}
	for l.i < len(s) && isDigit(s[l.i]) {
		l.i++
	}
	double := false
	if l.i+1 < len(s) && s[l.i] == '.' && isDigit(s[l.i+1]) {
		double = true
		l.i++
		for l.i < len(s) && isDigit(s[l.i]) {
			l.i++
		}
	}
	if l.i < len(s) && (s[l.i] == 'e' || s[l.i] == 'E') {
		j := l.i + 1
		if j < len(s) && (s[j] == '+' || s[j] == '-') {
			j++
		}
		if j >= len(s) || !isDigit(s[j]) {
			return token{}, errorf(l.i, "exponent has no digits")
		}
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		l.i = j
		double = true
	}
	if double {
		if err := l.noIdentAfter(); err != nil {
			return token{}, err
		}
		return token{kind: tokDouble, pos: start, text: s[start:l.i]}, nil
	}
	return l.intSuffix(start, s[start:l.i])
}

func (l *lexer) intSuffix(start int, digits string) (token, *Error) {
	if l.i < len(l.src) && (l.src[l.i] == 'u' || l.src[l.i] == 'U') {
		l.i++
		if err := l.noIdentAfter(); err != nil {
			return token{}, err
		}
		return token{kind: tokUint, pos: start, text: digits}, nil
	}
	if err := l.noIdentAfter(); err != nil {
		return token{}, err
	}
	return token{kind: tokInt, pos: start, text: digits}, nil
}

// noIdentAfter refuses "12abc" and "1.5x", which would otherwise lex as a
// number followed by an identifier.
func (l *lexer) noIdentAfter() *Error {
	if l.i < len(l.src) && (isIdentByte(l.src[l.i]) || l.src[l.i] == '.' && l.i+1 < len(l.src) && isDigit(l.src[l.i+1])) {
		return errorf(l.i, "unexpected %q after number", l.src[l.i])
	}
	return nil
}

// str reads a quoted string starting at the quote at l.i (after any r or b
// prefix, which start points at). raw strings keep backslashes as written.
func (l *lexer) str(start int, raw bool) (token, *Error) {
	s := l.src
	q := s[l.i]
	triple := l.i+2 < len(s) && s[l.i+1] == q && s[l.i+2] == q
	if triple {
		l.i += 3
	} else {
		l.i++
	}
	var b strings.Builder
	for {
		if l.i >= len(s) {
			return token{}, errorf(start, "string is not terminated")
		}
		c := s[l.i]
		if triple {
			if c == q && l.i+2 < len(s) && s[l.i+1] == q && s[l.i+2] == q {
				l.i += 3
				break
			}
		} else {
			if c == q {
				l.i++
				break
			}
			if c == '\n' || c == '\r' {
				return token{}, errorf(l.i, "newline in string; use a triple-quoted string")
			}
		}
		if c == '\\' && !raw {
			if err := l.escape(&b, q); err != nil {
				return token{}, err
			}
			continue
		}
		r, size := utf8.DecodeRuneInString(s[l.i:])
		if r == utf8.RuneError && size == 1 {
			return token{}, errorf(l.i, "string is not valid UTF-8")
		}
		b.WriteString(s[l.i : l.i+size])
		l.i += size
	}
	return token{kind: tokString, pos: start, text: b.String()}, nil
}

func (l *lexer) escape(b *strings.Builder, q byte) *Error {
	s := l.src
	at := l.i
	if l.i+1 >= len(s) {
		return errorf(at, "string ends inside an escape")
	}
	c := s[l.i+1]
	l.i += 2
	switch c {
	case 'a':
		b.WriteByte('\a')
	case 'b':
		b.WriteByte('\b')
	case 'f':
		b.WriteByte('\f')
	case 'n':
		b.WriteByte('\n')
	case 'r':
		b.WriteByte('\r')
	case 't':
		b.WriteByte('\t')
	case 'v':
		b.WriteByte('\v')
	case '\\', '\'', '"', '`', '?':
		b.WriteByte(c)
	case 'x', 'X', 'u', 'U':
		n := 2
		switch c {
		case 'u':
			n = 4
		case 'U':
			n = 8
		}
		if l.i+n > len(s) {
			return errorf(at, "escape needs %d hexadecimal digits", n)
		}
		v, err := strconv.ParseUint(s[l.i:l.i+n], 16, 32)
		if err != nil {
			return errorf(at, "escape needs %d hexadecimal digits", n)
		}
		l.i += n
		// In a string, as CEL defines it, \xHH is the code point U+00HH.
		r := rune(v)
		if !utf8.ValidRune(r) {
			return errorf(at, "escape is not a valid code point")
		}
		b.WriteRune(r)
	case '0', '1', '2', '3':
		if l.i+2 > len(s) || !isOctal(s[l.i]) || !isOctal(s[l.i+1]) {
			return errorf(at, "octal escape needs three digits")
		}
		v := (int(c-'0') << 6) | (int(s[l.i]-'0') << 3) | int(s[l.i+1]-'0')
		l.i += 2
		b.WriteRune(rune(v)) // a code point, like \x
	default:
		return errorf(at, "unknown escape \\%c", c)
	}
	return nil
}

func isOctal(c byte) bool { return '0' <= c && c <= '7' }
