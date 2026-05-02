package timestamp

import (
	"fmt"
	"math"
	"time"
)

var (
	ErrTimestampExpired = fmt.Errorf("timestamp expired")
)

// Clock abstracts time source for deterministic testing.
type Clock interface {
	Now() time.Time
}

// ValidateWindow checks if timestamp is within replay window using injected clock.
// Returns ErrTimestampExpired if absolute delta exceeds window.
func ValidateWindow(clock Clock, ts time.Time, window time.Duration) error {
	if clock == nil {
		return fmt.Errorf("nil clock")
	}

	// Zero timestamp means no timestamp semantics - always valid
	if ts.IsZero() {
		return nil
	}

	now := clock.Now()
	delta := now.Sub(ts)
	
	// Check absolute delta against window
	if math.Abs(float64(delta)) > float64(window) {
		return ErrTimestampExpired
	}

	return nil
}
