package webhookseal

import "time"

// Clock abstracts time source for deterministic timestamp validation.
type Clock interface {
	Now() time.Time
}
