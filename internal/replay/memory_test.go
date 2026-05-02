package replay

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStore_Atomicity(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	inserted, err := s.MarkIfAbsent(ctx, "stripe", "evt_1", time.Second)
	if err != nil {
		t.Fatalf("unexpected error on first insert: %v", err)
	}
	if !inserted {
		t.Fatalf("expected first insert to return true")
	}

	inserted, err = s.MarkIfAbsent(ctx, "stripe", "evt_1", time.Second)
	if err != nil {
		t.Fatalf("unexpected error on duplicate insert: %v", err)
	}
	if inserted {
		t.Fatalf("expected duplicate insert within ttl to return false")
	}
}

func TestMemoryStore_TTLExpiry(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	inserted, err := s.MarkIfAbsent(ctx, "stripe", "evt_2", 20*time.Millisecond)
	if err != nil || !inserted {
		t.Fatalf("expected first insert true, got inserted=%v err=%v", inserted, err)
	}

	time.Sleep(40 * time.Millisecond)

	inserted, err = s.MarkIfAbsent(ctx, "stripe", "evt_2", 20*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error after ttl expiry: %v", err)
	}
	if !inserted {
		t.Fatalf("expected insert after ttl expiry to return true")
	}
}

func TestMemoryStore_Concurrency(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	const workers = 128
	var wg sync.WaitGroup
	var insertedCount int32

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			inserted, err := s.MarkIfAbsent(ctx, "stripe", "evt_concurrent", time.Second)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if inserted {
				atomic.AddInt32(&insertedCount, 1)
			}
		}()
	}

	wg.Wait()

	if got := atomic.LoadInt32(&insertedCount); got != 1 {
		t.Fatalf("expected exactly one successful insert, got %d", got)
	}
}

func TestMemoryStore_ScopeIsolation(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	insertedA, err := s.MarkIfAbsent(ctx, "stripe", "same_id", time.Second)
	if err != nil {
		t.Fatalf("unexpected error for first scope: %v", err)
	}
	insertedB, err := s.MarkIfAbsent(ctx, "github", "same_id", time.Second)
	if err != nil {
		t.Fatalf("unexpected error for second scope: %v", err)
	}

	if !insertedA || !insertedB {
		t.Fatalf("expected same id across different scopes to insert independently")
	}
}
