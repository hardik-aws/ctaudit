package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

// scanSpec describes one generic scan: which keys to fetch, how to decode an
// object into records of type T, and how a worker folds records into its
// private shard of type S.
type scanSpec[T, S any] struct {
	prefixes     []string
	listWorkers  int
	fetchWorkers int
	// keep selects which listed keys are fetched.
	keep func(key string) bool
	// skip, when set, drops a kept key before it is fetched. Serve mode uses
	// it to leave out objects an earlier tick already read.
	skip func(key string) bool
	// decode turns one object into records. It may return records together
	// with an error (e.g. some lines were unparseable); the error is recorded
	// and the records are still visited.
	decode   func(key string, r io.Reader) ([]T, error)
	newShard func() S
	// visit folds one record into a shard and reports whether it matched
	// the filters.
	visit func(S, T) bool
	// log, when set, receives debug lines per prefix and per object.
	log *slog.Logger
}

// scanOutput is what every scan returns before type-specific merging.
type scanOutput[S any] struct {
	shards         []S
	objectsScanned int
	recordsRead    int
	errs           []string
	// readKeys lists, sorted, every object whose records were visited.
	readKeys []string
}

// scan fans prefixes out to listers and keys out to fetchers. Each fetcher
// owns one shard, so nothing on the per-record path is shared. Per-object
// errors are collected; only context cancellation returns an error.
func scan[T, S any](ctx context.Context, store s3src.ObjectStore, spec scanSpec[T, S]) (scanOutput[S], error) {
	listWorkers := spec.listWorkers
	if listWorkers <= 0 {
		listWorkers = defaultListWorkers
	}
	fetchWorkers := spec.fetchWorkers
	if fetchWorkers <= 0 {
		fetchWorkers = defaultFetchWorkers
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	prefixCh := make(chan string)
	keyCh := make(chan string, fetchWorkers*2)

	// Stage 0: feed prefixes.
	go func() {
		defer close(prefixCh)
		for _, p := range spec.prefixes {
			select {
			case prefixCh <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Stage 1: list each prefix, page by page, emitting wanted keys.
	var listErrMu sync.Mutex
	var listErrs []string
	var listWG sync.WaitGroup
	for i := 0; i < listWorkers; i++ {
		listWG.Add(1)
		go func() {
			defer listWG.Done()
			for prefix := range prefixCh {
				token := ""
				started := time.Now()
				var pages, listed, kept, filtered, skipped int
				for {
					keys, next, err := store.ListPage(ctx, prefix, token)
					if err != nil {
						if spec.log != nil {
							spec.log.Debug("list failed", "prefix", prefix, "page", pages+1, "err", err)
						}
						listErrMu.Lock()
						if len(listErrs) < maxRecordedErrors {
							listErrs = append(listErrs, fmt.Sprintf("list %s: %v", prefix, err))
						}
						listErrMu.Unlock()
						break
					}
					pages++
					listed += len(keys)
					for _, k := range keys {
						if !spec.keep(k) {
							filtered++
							continue
						}
						if spec.skip != nil && spec.skip(k) {
							skipped++
							continue
						}
						kept++
						select {
						case keyCh <- k:
						case <-ctx.Done():
							return
						}
					}
					if next == "" {
						break
					}
					token = next
				}
				if spec.log != nil {
					spec.log.Debug("listed prefix", "prefix", prefix, "pages", pages, "listed", listed,
						"fetch", kept, "filtered", filtered, "skipped_seen", skipped, "dur", time.Since(started))
				}
			}
		}()
	}
	go func() {
		listWG.Wait()
		close(keyCh)
	}()

	// Stage 2: fetch, decode, and fold into private shards.
	type worker struct {
		shard          S
		objectsScanned int
		recordsRead    int
		errs           []string
		readKeys       []string
	}
	workers := make([]*worker, fetchWorkers)
	var fetchWG sync.WaitGroup
	for i := range workers {
		w := &worker{shard: spec.newShard()}
		workers[i] = w
		fetchWG.Add(1)
		go func() {
			defer fetchWG.Done()
			for key := range keyCh {
				if ctx.Err() != nil {
					return
				}
				started := time.Now()
				recs, size, err := fetchDecode(ctx, store, key, spec.decode)
				if err != nil && spec.log != nil {
					spec.log.Debug("object failed", "key", key, "bytes", size, "records", len(recs), "dur", time.Since(started), "err", err)
				}
				if err != nil && len(w.errs) < maxRecordedErrors {
					w.errs = append(w.errs, err.Error())
				}
				if err != nil && recs == nil {
					continue
				}
				// The records are visited below, so the key counts as read
				// even when decode also reported bad lines: reading it again
				// would count those records twice.
				w.readKeys = append(w.readKeys, key)
				w.objectsScanned++
				w.recordsRead += len(recs)
				matched := 0
				for _, rec := range recs {
					if spec.visit(w.shard, rec) {
						matched++
					}
				}
				if spec.log != nil && err == nil {
					spec.log.Debug("object read", "key", key, "bytes", size, "records", len(recs), "matched", matched, "dur", time.Since(started))
				}
			}
		}()
	}
	fetchWG.Wait()

	if err := ctx.Err(); err != nil {
		return scanOutput[S]{}, err
	}

	out := scanOutput[S]{shards: make([]S, 0, len(workers))}
	for _, w := range workers {
		out.shards = append(out.shards, w.shard)
		out.objectsScanned += w.objectsScanned
		out.recordsRead += w.recordsRead
		out.errs = append(out.errs, w.errs...)
		out.readKeys = append(out.readKeys, w.readKeys...)
	}
	sort.Strings(out.readKeys)
	out.errs = append(out.errs, listErrs...)
	return out, nil
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// fetchDecode reads and decodes one object. It also returns how many
// compressed bytes were read.
func fetchDecode[T any](ctx context.Context, store s3src.ObjectStore, key string, decode func(string, io.Reader) ([]T, error)) ([]T, int64, error) {
	rc, err := store.Get(ctx, key)
	if err != nil {
		return nil, 0, fmt.Errorf("get %s: %w", key, err)
	}
	defer rc.Close()

	cr := &countingReader{r: rc}
	recs, err := decode(key, cr)
	if err != nil {
		return recs, cr.n, fmt.Errorf("decode %s: %w", key, err)
	}
	return recs, cr.n, nil
}
