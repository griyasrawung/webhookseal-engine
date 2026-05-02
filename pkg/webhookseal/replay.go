package webhookseal

import (
	"context"
	"time"
)

// ReplayStore tracks webhook IDs to prevent replay attacks.
type ReplayStore interface {
	// MarkIfAbsent marks (scope,id) as seen for ttl and returns true if newly inserted.
	MarkIfAbsent(ctx context.Context, scope string, id string, ttl time.Duration) (inserted bool, err error)
}
