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

// Orders returns the number of orders held in memory.
func (ca *CA) Orders() int {
	n := 0
	ca.orders.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}
