package acmeerrors_test

import (
	"errors"
	"testing"

	"geomys.org/magnolia/internal/acmeerrors"
)

func TestCategory(t *testing.T) {
	inner := acmeerrors.Internal("couldn't open database: %w", errors.New("foo"))
	for _, tt := range []struct {
		err  acmeerrors.Error
		want string
	}{
		{acmeerrors.New("malformed", 400, "invalid JSON payload"), "invalid JSON payload"},
		{acmeerrors.New("malformed", 400, "bad header %q", "x"), "bad header"},
		{inner, "couldn't open database"},
		{acmeerrors.Internal("transaction failed: %w", inner), "transaction failed: couldn't open database"},
		{acmeerrors.Internal("%w", inner), "couldn't open database"},
	} {
		if got := tt.err.Category(); got != tt.want {
			t.Errorf("%v: got category %q, want %q", tt.err, got, tt.want)
		}
	}
}
