package acmeerrors

import (
	"errors"
	"fmt"
	"maps"
	"strings"
)

// Error is an error with additional metadata to be served as an ACME problem
// document, as defined by RFC 8555, Section 6.7, and for metrics.
//
// Error is an interface rather than a concrete pointer type so that a nil Error
// assigned to an error variable stays nil, avoiding the typed nil trap.
type Error interface {
	error

	// Unwrap returns the error wrapped with %w by the constructor, if any,
	// so that errors.Is and errors.As see through the problem document.
	Unwrap() error
	// Type is the problem type URN, such as "urn:ietf:params:acme:error:malformed".
	Type() string
	// Detail is the human-readable explanation of the problem.
	Detail() string
	// Status is the HTTP status code to respond with.
	Status() int
	// Category is a low-cardinality label for metrics, derived from the
	// constructor's format string.
	Category() string
	// Fields are additional members of the problem document, such as
	// "algorithms" for badSignatureAlgorithm.
	Fields() map[string]any
	// WithField returns a copy of the Error with an additional field.
	WithField(key string, value any) Error
	// Headers are response headers to set alongside the problem document,
	// such as "Location" for a badPublicKey conflict with another account.
	Headers() map[string]string
	// WithHeader returns a copy of the Error with an additional header.
	WithHeader(key, value string) Error
}

type problem struct {
	typ      string
	status   int
	category string
	err      error
	fields   map[string]any
	headers  map[string]string
}

func (p *problem) Error() string              { return "[" + p.typ + "] " + p.err.Error() }
func (p *problem) Unwrap() error              { return p.err }
func (p *problem) Type() string               { return p.typ }
func (p *problem) Detail() string             { return p.err.Error() }
func (p *problem) Status() int                { return p.status }
func (p *problem) Category() string           { return p.category }
func (p *problem) Fields() map[string]any     { return p.fields }
func (p *problem) Headers() map[string]string { return p.headers }

func (p *problem) WithField(key string, value any) Error {
	q := *p
	q.fields = maps.Clone(p.fields)
	if q.fields == nil {
		q.fields = make(map[string]any)
	}
	q.fields[key] = value
	return &q
}

func (p *problem) WithHeader(key, value string) Error {
	q := *p
	q.headers = maps.Clone(p.headers)
	if q.headers == nil {
		q.headers = make(map[string]string)
	}
	q.headers[key] = value
	return &q
}

// newProblem formats the detail like fmt.Errorf and derives the category
// from the format string, as documented on [Error.Category].
func newProblem(typ string, status int, format string, a ...any) *problem {
	category, _, _ := strings.Cut(format, "%")
	category = strings.TrimSpace(category)
	category = strings.TrimSuffix(category, ":")
	err := fmt.Errorf(format, a...)
	if inner, ok := errors.AsType[Error](err); ok {
		if category == "" {
			category = inner.Category()
		} else {
			category += ": " + inner.Category()
		}
	}
	return &problem{typ: typ, status: status, category: category, err: err}
}

// New returns an Error with a standard ACME problem type. The format and
// arguments are interpreted like fmt.Errorf, so %w is allowed.
func New(t string, status int, format string, a ...any) Error {
	return newProblem("urn:ietf:params:acme:error:"+t, status, format, a...)
}

// Custom returns an Error with a Magnolia-specific problem type. The format
// and arguments are interpreted like fmt.Errorf, so %w is allowed.
func Custom(t string, status int, format string, a ...any) Error {
	return newProblem("https://magnolia-ca.com/acme/error/"+t, status, format, a...)
}

// Internal returns a serverInternal Error with status 500. The format and
// arguments are interpreted like fmt.Errorf, so %w is allowed.
func Internal(format string, a ...any) Error {
	return newProblem("urn:ietf:params:acme:error:serverInternal", 500, format, a...)
}

// Render produces a map representation of the Error suitable for JSON encoding.
func Render(err Error) map[string]any {
	j := map[string]any{
		"type":   err.Type(),
		"detail": err.Detail(),
	}
	maps.Copy(j, err.Fields())
	return j
}
