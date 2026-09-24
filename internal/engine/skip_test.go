package engine

import (
	"context"
	"io"
	"slices"
	"sync"
	"testing"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

// countingStore records every Get so tests can prove skipped keys are never
// fetched.
type countingStore struct {
	*s3src.MemStore
	mu   sync.Mutex
	gets []string
}

func (c *countingStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	c.mu.Lock()
	c.gets = append(c.gets, key)
	c.mu.Unlock()
	return c.MemStore.Get(ctx, key)
}

func TestRunSkipsKeysAndReportsReadKeys(t *testing.T) {
	seen, fresh, bad := key("seen"), key("fresh"), key("bad")
	store := &countingStore{MemStore: s3src.NewMemStore(map[string][]byte{
		seen:  objectWith(t, "DeleteBucket", "arn:aws:iam::1:user/alice", "", "10"),
		fresh: objectWith(t, "PutObject", "arn:aws:iam::1:user/bob", "", "11"),
		bad:   []byte("this is not gzip"),
	})}

	res, err := Run(context.Background(), store, Options{
		Scope: testScope(),
		Skip:  func(k string) bool { return k == seen },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if slices.Contains(store.gets, seen) {
		t.Errorf("Get called for skipped key; gets = %v", store.gets)
	}
	if len(store.gets) != 2 {
		t.Errorf("gets = %v, want exactly the fresh and bad keys", store.gets)
	}
	if !slices.Equal(res.ReadKeys, []string{fresh}) {
		t.Errorf("ReadKeys = %v, want only %s (bad gzip is not read)", res.ReadKeys, fresh)
	}
	if len(res.Errors) != 1 || res.RecordsRead != 1 {
		t.Errorf("Errors = %v, RecordsRead = %d; want one error and one record", res.Errors, res.RecordsRead)
	}
}

func TestRunELBSkipsKeysAndReportsReadKeys(t *testing.T) {
	seen := elbKey("app.tiles.98e3", "a.log.gz")
	fresh := elbKey("app.tiles.98e3", "b.log.gz")
	bad := elbKey("app.tiles.98e3", "c.log.gz")
	store := &countingStore{MemStore: s3src.NewMemStore(map[string][]byte{
		seen:  gz(t, albLine("2026-09-23T07:15:47.000000Z", "1.1.1.1", "200", "/", 0.003)+"\n"),
		fresh: gz(t, albLine("2026-09-23T08:00:00.000000Z", "2.2.2.2", "502", "/", 1.5)+"\n"),
		bad:   []byte("this is not gzip"),
	})}

	res, err := RunELB(context.Background(), store, ELBOptions{
		Scope: elbScope(),
		Skip:  func(k string) bool { return k == seen },
	})
	if err != nil {
		t.Fatalf("RunELB: %v", err)
	}
	if slices.Contains(store.gets, seen) || len(store.gets) != 2 {
		t.Errorf("gets = %v, want the fresh and bad keys only", store.gets)
	}
	if !slices.Equal(res.ReadKeys, []string{fresh}) {
		t.Errorf("ReadKeys = %v, want only %s", res.ReadKeys, fresh)
	}
	if len(res.Errors) != 1 || res.RecordsRead != 1 {
		t.Errorf("Errors = %v, RecordsRead = %d; want one error and one record", res.Errors, res.RecordsRead)
	}
}
