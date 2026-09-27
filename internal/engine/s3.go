package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/s3log"
	"github.com/gsmappdev/ctaudit/internal/s3rules"
	"github.com/gsmappdev/ctaudit/internal/s3src"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// S3Options configures one S3 server access log scan.
type S3Options struct {
	// Scope selects days and, for the partitioned layout, accounts and
	// regions. Its BasePrefix is the target prefix, used verbatim.
	Scope s3src.Scope
	// Layout is s3src.S3LayoutSimple (the default when empty) or
	// s3src.S3LayoutPartitioned.
	Layout string
	// SourceBuckets narrows partitioned discovery to buckets whose name
	// contains one of these substrings (case-insensitive). Record-level
	// filtering by bucket is Filter.Buckets.
	SourceBuckets []string
	Filter        s3log.Filter
	// DeniedThreshold, DeleteThreshold, and EgressBytes are passed through
	// to s3rules.Detect.
	DeniedThreshold int
	DeleteThreshold int
	EgressBytes     int64
	ListWorkers     int
	FetchWorkers    int
	// MaxEvents caps how many matching entries are retained for the request
	// table. Statistics are unaffected.
	MaxEvents int
	// Emit, when set, is called once per fetch worker. The function it
	// returns receives every request that passes the filter, uncapped by
	// MaxEvents, from that worker's goroutine only.
	Emit func() func(s3log.Entry)
	// Skip, when set, leaves out every object whose key it returns true for.
	// It is called from the list workers and must be safe for concurrent use.
	Skip func(key string) bool
	// Debug, when set, receives one line per listed prefix and per object.
	Debug *slog.Logger
}

// Rules returns the findings options these scan options carry.
func (o S3Options) Rules() s3rules.Options {
	return s3rules.Options{DeniedThreshold: o.DeniedThreshold, DeleteThreshold: o.DeleteThreshold, EgressBytes: o.EgressBytes}
}

// S3Result is everything the S3 report needs.
type S3Result struct {
	Summary         *stats.S3Summary
	Findings        []findings.Finding
	FindingsDropped int
	Matches         []s3log.Entry
	// Layout is the key layout scanned.
	Layout string
	// SourceBuckets lists, sorted, every source bucket discovered and kept
	// by the partitioned layout; it is nil for the simple layout.
	SourceBuckets []string
	// Prefixes is how many prefixes were listed; FirstPrefix is the first,
	// for the "nothing found" warning.
	Prefixes       int
	FirstPrefix    string
	ObjectsScanned int
	RecordsRead    int
	MatchedRecords int
	Errors         []string
	// ReadKeys lists, sorted, every object whose records were read.
	ReadKeys []string
	Elapsed  time.Duration
}

type s3Shard struct {
	summary        *stats.S3Summary
	matches        []s3log.Entry
	matchedRecords int
	emit           func(s3log.Entry)
}

// RunS3 builds the prefixes for the layout, scans them, and returns the
// aggregated result with findings. Per-object errors are collected into
// S3Result.Errors rather than aborting the scan; a failed source bucket
// discovery listing aborts it, because the scope would silently shrink.
func RunS3(ctx context.Context, store s3src.ObjectStore, opts S3Options) (S3Result, error) {
	started := time.Now()

	scope := opts.Scope
	layout := opts.Layout
	if layout == "" {
		layout = s3src.S3LayoutSimple
	}
	if scope.End.Before(scope.Start) {
		return S3Result{}, errors.New("empty scan scope: need a valid date range")
	}
	if err := ctx.Err(); err != nil {
		return S3Result{}, err
	}

	var prefixes, buckets []string
	switch layout {
	case s3src.S3LayoutSimple:
		prefixes = scope.S3SimplePrefixes()
	case s3src.S3LayoutPartitioned:
		if len(scope.Accounts) == 0 || len(scope.Regions) == 0 {
			return S3Result{}, errors.New("empty scan scope: the partitioned layout needs at least one account and one region")
		}
		var err error
		if prefixes, buckets, err = scope.S3PartitionedPrefixes(ctx, store, opts.SourceBuckets); err != nil {
			return S3Result{}, err
		}
	default:
		return S3Result{}, fmt.Errorf("unknown S3 log layout %q (want %s or %s)", layout, s3src.S3LayoutSimple, s3src.S3LayoutPartitioned)
	}
	if opts.Debug != nil {
		opts.Debug.Debug("s3 prefixes built", "layout", layout, "prefixes", len(prefixes), "source_buckets", len(buckets))
	}

	res := S3Result{Summary: stats.NewS3Summary(), Layout: layout, SourceBuckets: buckets, Prefixes: len(prefixes)}
	if len(prefixes) > 0 {
		res.FirstPrefix = prefixes[0]
	}
	if len(prefixes) == 0 {
		res.Elapsed = time.Since(started)
		return res, nil
	}

	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}

	out, err := scan(ctx, store, scanSpec[s3log.Entry, *s3Shard]{
		prefixes:     prefixes,
		listWorkers:  opts.ListWorkers,
		fetchWorkers: opts.FetchWorkers,
		keep:         s3log.IsLogKey,
		skip:         opts.Skip,
		decode:       s3log.Decode,
		newShard: func() *s3Shard {
			sh := &s3Shard{summary: stats.NewS3Summary()}
			if opts.Emit != nil {
				sh.emit = opts.Emit()
			}
			return sh
		},
		log: opts.Debug,
		visit: func(sh *s3Shard, e s3log.Entry) bool {
			if !opts.Filter.Match(e) {
				return false
			}
			sh.matchedRecords++
			if sh.emit != nil {
				sh.emit(e)
			}
			sh.summary.Add(e)
			sh.matches = append(sh.matches, e)
			// Keep each shard's earliest maxEvents entries. Trimming at 2x
			// amortises the sort so the per-entry cost stays constant.
			if len(sh.matches) >= 2*maxEvents {
				sh.matches = earliestS3(sh.matches, maxEvents)
			}
			return true
		},
	})
	if err != nil {
		return S3Result{}, err
	}

	res.ObjectsScanned, res.RecordsRead, res.Errors, res.ReadKeys = out.objectsScanned, out.recordsRead, out.errs, out.readKeys
	for _, sh := range out.shards {
		res.Summary.Merge(sh.summary)
		res.MatchedRecords += sh.matchedRecords
		res.Matches = append(res.Matches, sh.matches...)
	}
	res.Matches = earliestS3(res.Matches, maxEvents)
	res.Findings, res.FindingsDropped = s3rules.Detect(res.Summary, opts.Rules())

	res.Elapsed = time.Since(started)
	return res, nil
}

// earliestS3 sorts entries by time and keeps at most n of them.
func earliestS3(entries []s3log.Entry, n int) []s3log.Entry {
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Time.Before(entries[j].Time) })
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}
