package acmetest

import (
	"encoding/json/v2"
	"fmt"
	"strconv"
	"strings"
)

// A path selects a value inside a decoded JSON document. It is a sequence of
// segments, each of which is one of
//
//	.name        a member of an object
//	[3]          an element of an array
//	[key=value]  the first element of an array whose member key has value
//
// The empty path selects the whole document.
type path []segment

type segment struct {
	name  string
	index int
	key   string
	value string
	kind  segmentKind
}

type segmentKind int

const (
	segMember segmentKind = iota
	segIndex
	segFilter
)

// parsePath parses a path. It returns the parsed path and the unparsed
// remainder of s, which is non-empty if s continues with something that
// is not a segment.
func parsePath(s string) (path, string, error) {
	var p path
	for s != "" {
		switch s[0] {
		case '.':
			i := 1
			for i < len(s) && isNameChar(s[i]) {
				i++
			}
			if i == 1 {
				return p, s, nil
			}
			p = append(p, segment{kind: segMember, name: s[1:i]})
			s = s[i:]
		case '[':
			end := strings.IndexByte(s, ']')
			if end < 0 {
				return nil, "", fmt.Errorf("unterminated [ in path %q", s)
			}
			inner := s[1:end]
			if k, v, ok := strings.Cut(inner, "="); ok {
				p = append(p, segment{kind: segFilter, key: k, value: v})
			} else {
				n, err := strconv.Atoi(inner)
				if err != nil {
					return nil, "", fmt.Errorf("invalid index %q in path", inner)
				}
				p = append(p, segment{kind: segIndex, index: n})
			}
			s = s[end+1:]
		default:
			return p, s, nil
		}
	}
	return p, "", nil
}

func isNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// lookup evaluates the path against v. It returns false if the path does not
// select anything.
func (p path) lookup(v any) (any, bool) {
	for _, seg := range p {
		switch seg.kind {
		case segMember:
			obj, ok := v.(map[string]any)
			if !ok {
				return nil, false
			}
			v, ok = obj[seg.name]
			if !ok {
				return nil, false
			}
		case segIndex:
			arr, ok := v.([]any)
			if !ok || seg.index < 0 || seg.index >= len(arr) {
				return nil, false
			}
			v = arr[seg.index]
		case segFilter:
			arr, ok := v.([]any)
			if !ok {
				return nil, false
			}
			found := false
			for _, e := range arr {
				obj, ok := e.(map[string]any)
				if ok && stringify(obj[seg.key]) == seg.value {
					v, found = e, true
					break
				}
			}
			if !found {
				return nil, false
			}
		}
	}
	return v, true
}

// stringify renders a decoded JSON value for comparison and substitution:
// strings as themselves, everything else as canonical JSON.
func stringify(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// A lookup resolves a variable name to its value.
type lookup func(name string) (any, bool)

// expand replaces $name and $name.path[0] references in s with the values of
// the variables. $$ is a literal dollar sign. Unknown variables and paths
// that select nothing are errors.
func expand(s string, vars lookup) (string, error) {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '$')
		if i < 0 {
			b.WriteString(s)
			return b.String(), nil
		}
		b.WriteString(s[:i])
		s = s[i+1:]
		if strings.HasPrefix(s, "$") {
			b.WriteByte('$')
			s = s[1:]
			continue
		}
		j := 0
		for j < len(s) && isNameChar(s[j]) {
			j++
		}
		if j == 0 {
			return "", fmt.Errorf("invalid variable reference at %q", "$"+s)
		}
		_, rest, err := parsePath(s[j:])
		if err != nil {
			return "", err
		}
		ref := "$" + s[:len(s)-len(rest)]
		v, err := evaluate(ref, vars)
		if err != nil {
			return "", err
		}
		b.WriteString(stringify(v))
		s = rest
	}
}

// evaluate resolves a variable reference like $name or $name.path[0],
// keeping the JSON type of the value. A path that selects nothing is an
// error.
func evaluate(expr string, vars lookup) (any, error) {
	v, ok, err := resolve(expr, vars)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%s does not select a value", expr)
	}
	return v, nil
}

// resolve evaluates a variable reference. It returns false if the variable
// is defined but the path selects nothing, and an error for anything else.
func resolve(expr string, vars lookup) (any, bool, error) {
	if !strings.HasPrefix(expr, "$") {
		return nil, false, fmt.Errorf("%q is not a variable reference", expr)
	}
	j := 1
	for j < len(expr) && isNameChar(expr[j]) {
		j++
	}
	name := expr[1:j]
	p, rest, err := parsePath(expr[j:])
	if err != nil {
		return nil, false, err
	}
	if name == "" || rest != "" {
		return nil, false, fmt.Errorf("%q is not a variable reference", expr)
	}
	v, ok := vars(name)
	if !ok {
		return nil, false, fmt.Errorf("undefined variable $%s", name)
	}
	v, ok = p.lookup(v)
	return v, ok, nil
}
