package s3src

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"
)

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestMemStoreListPageFiltersByPrefixAndSortsKeys(t *testing.T) {
	store := NewMemStore(map[string][]byte{
		"AWSLogs/1/CloudTrail/us-east-1/2026/09/20/b.json.gz": []byte("b"),
		"AWSLogs/1/CloudTrail/us-east-1/2026/09/20/a.json.gz": []byte("a"),
		"AWSLogs/1/CloudTrail/us-east-1/2026/09/21/c.json.gz": []byte("c"),
	})

	keys, next, err := store.ListPage(context.Background(), "AWSLogs/1/CloudTrail/us-east-1/2026/09/20/", "")
	if err != nil {
		t.Fatalf("ListPage: %v", err)
	}
	if next != "" {
		t.Errorf("next = %q, want empty (single page)", next)
	}
	want := []string{
		"AWSLogs/1/CloudTrail/us-east-1/2026/09/20/a.json.gz",
		"AWSLogs/1/CloudTrail/us-east-1/2026/09/20/b.json.gz",
	}
	if len(keys) != len(want) {
		t.Fatalf("got %d keys, want %d: %v", len(keys), len(want), keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("keys[%d] = %q, want %q", i, keys[i], want[i])
		}
	}
}

func TestMemStoreListPagePaginates(t *testing.T) {
	store := NewMemStore(map[string][]byte{
		"p/a": []byte("a"),
		"p/b": []byte("b"),
		"p/c": []byte("c"),
	})
	store.PageSize = 2

	keys, next, err := store.ListPage(context.Background(), "p/", "")
	if err != nil {
		t.Fatalf("ListPage page 1: %v", err)
	}
	if len(keys) != 2 || next == "" {
		t.Fatalf("page 1 = %v, next = %q; want 2 keys and a continuation token", keys, next)
	}

	keys2, next2, err := store.ListPage(context.Background(), "p/", next)
	if err != nil {
		t.Fatalf("ListPage page 2: %v", err)
	}
	if len(keys2) != 1 || next2 != "" {
		t.Fatalf("page 2 = %v, next = %q; want 1 key and no continuation token", keys2, next2)
	}
	if keys2[0] != "p/c" {
		t.Errorf("page 2 key = %q, want p/c", keys2[0])
	}
}

func TestMemStoreGetReturnsContent(t *testing.T) {
	payload := gzipBytes(t, `{"Records":[]}`)
	store := NewMemStore(map[string][]byte{"p/one.json.gz": payload})

	rc, err := store.Get(context.Background(), "p/one.json.gz")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("Get returned different bytes than were stored")
	}
}

func TestMemStoreGetMissingKeyErrors(t *testing.T) {
	store := NewMemStore(nil)
	if _, err := store.Get(context.Background(), "nope"); err == nil {
		t.Fatal("Get of a missing key returned nil error")
	}
}

// Compile-time assertion that both stores satisfy the interface.
var (
	_ ObjectStore = (*MemStore)(nil)
	_ ObjectStore = (*S3Store)(nil)
)
