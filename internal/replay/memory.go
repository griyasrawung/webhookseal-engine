package replay

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory replay store with atomic check-and-insert semantics.
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]time.Time
}

// NewMemoryStore creates an empty in-memory replay store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string]time.Time)}
}

// MarkIfAbsent inserts a (scope,id) key if missing or expired.
func (s *MemoryStore) MarkIfAbsent(_ context.Context, scope string, id string, ttl time.Duration) (bool, error) {
	now := time.Now()
	key := scope + ":" + id

	s.mu.Lock()
	defer s.mu.Unlock()

	// Lazy cleanup of expired entries.
	for k, expiresAt := range s.items {
		if !expiresAt.After(now) {
			delete(s.items, k)
		}
	}

	if expiresAt, ok := s.items[key]; ok && expiresAt.After(now) {
		return false, nil
	}

	s.items[key] = now.Add(ttl)
	return true, nil
}
