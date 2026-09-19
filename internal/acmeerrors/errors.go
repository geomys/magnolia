package acmeerrors

import (
	"fmt"
	"maps"
	"strings"
)

// Error is an ACME problem document, as defined by RFC 8555, Section 6.7.
//
// Error is an interface rather than a concrete pointer type so that a nil
// Error assigned to an error variable stays nil, avoiding the typed nil trap.
type Error interface {
	error

	// Type is the problem type URN, such as "urn:ietf:params:acme:error:malformed".
	Type() string
	// Detail is the human-readable explanation of the problem.
	Detail() string
	// Status is the HTTP status code to respond with.
	Status() int
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
	typ     string
	detail  string
	status  int
	fields  map[string]any
	headers map[string]string
}

func (p *problem) Error() string              { return "[" + p.typ + "] " + p.detail }
func (p *problem) Type() string               { return p.typ }
func (p *problem) Detail() string             { return p.detail }
func (p *problem) Status() int                { return p.status }
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

// New returns an Error with a standard ACME problem type. The detail strings
// are joined with spaces.
func New(t string, status int, detail ...string) Error {
	return &problem{
		typ:    "urn:ietf:params:acme:error:" + t,
		detail: strings.Join(detail, " "),
		status: status,
	}
}

// Custom returns an Error with a Magnolia-specific problem type.
func Custom(t string, status int, detail string) Error {
	return &problem{
		typ:    "https://magnolia-ca.com/acme/error/" + t,
		detail: detail,
		status: status,
	}
}

// Internal returns a serverInternal Error with status 500. The format and
// arguments are interpreted like fmt.Errorf, so %w is allowed.
func Internal(format string, a ...any) Error {
	return &problem{
		typ:    "urn:ietf:params:acme:error:serverInternal",
		detail: fmt.Errorf(format, a...).Error(),
		status: 500,
	}
}
