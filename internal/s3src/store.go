package s3src

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
)

// ObjectStore is the minimal read-only view of object storage that the audit
// engine needs. Keeping it this small means the whole pipeline can be tested
// against MemStore without AWS credentials.
type ObjectStore interface {
	// ListPage returns one page of keys under prefix. Pass an empty token for
	// the first page; a non-empty returned token means more pages remain.
	ListPage(ctx context.Context, prefix, token string) (keys []string, next string, err error)
	// Get opens the object at key. The caller closes the reader.
	Get(ctx context.Context, key string) (io.ReadCloser, error)
}

// MemStore is an in-memory ObjectStore for tests.
type MemStore struct {
	objects map[string][]byte
	// PageSize caps how many keys ListPage returns at once. Zero means all.
	PageSize int
}

// NewMemStore builds a MemStore over the given key/content map.
func NewMemStore(objects map[string][]byte) *MemStore {
	if objects == nil {
		objects = map[string][]byte{}
	}
	return &MemStore{objects: objects}
}

// ListPage returns the sorted keys under prefix, honouring PageSize. The
// continuation token is the integer offset of the next key.
func (m *MemStore) ListPage(_ context.Context, prefix, token string) ([]string, string, error) {
	var all []string
	for k := range m.objects {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			all = append(all, k)
		}
	}
	sort.Strings(all)

	offset := 0
	if token != "" {
		n, err := strconv.Atoi(token)
		if err != nil {
			return nil, "", fmt.Errorf("bad continuation token %q: %w", token, err)
		}
		offset = n
	}
	if offset > len(all) {
		offset = len(all)
	}
	rest := all[offset:]

	if m.PageSize > 0 && len(rest) > m.PageSize {
		return rest[:m.PageSize], strconv.Itoa(offset + m.PageSize), nil
	}
	return rest, "", nil
}

// Get returns the stored bytes for key.
func (m *MemStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	b, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("object not found: %s", key)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}
