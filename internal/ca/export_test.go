package ca

import (
	"time"
)

func init() {
	// The tests use a long sequencing period, to sleep for hours of fake time
	// without sequencing thousands of empty pools.
	issueTimeout = 2 * time.Hour
}

func IndexPath(n int64) string {
	return indexPath(n)
}
