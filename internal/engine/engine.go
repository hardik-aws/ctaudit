// Package engine runs the scan: it fans prefixes out to listers, objects out
// to fetchers, and folds the decoded records into per-worker shards that are
// merged once at the end.
package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/query"
	"github.com/gsmappdev/ctaudit/internal/s3src"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// Default worker counts. Listing is cheap and latency-bound; fetching is
// bandwidth- and CPU-bound because every object must be gunzipped.
const (
	defaultListWorkers  = 8
	defaultFetchWorkers = 32
	defaultMaxEvents    = 200
	maxRecordedErrors   = 50
)

// Options configures one scan.
type Options struct {
	Scope        s3src.Scope
	Filter       query.Filter
	Rules        []findings.Rule
	ListWorkers  int
	FetchWorkers int
	// MaxEvents caps how many matching records are retained for the event
	// table. Statistics and findings are unaffected.
	MaxEvents int
	// FindingsCap overrides the per-detector findings cap (see
	// findings.Detector.Max). Zero keeps the detector's default cap; tests
	// use a small value to exercise cap behavior without generating
	// thousands of records.
	FindingsCap int
	// Emit, when set, is called once per fetch worker. The function it
	// returns receives every record that passes the filter, uncapped by
	// MaxEvents, and is only ever called from that worker's goroutine.
	Emit func() func(ctevent.Record)
	// Skip, when set, leaves out every object whose key it returns true for.
	// It is called from the list workers and must be safe for concurrent use.
	Skip func(key string) bool
	// Debug, when set, receives one line per listed prefix and per object.
	Debug *slog.Logger
}

// Result is everything a report needs.
type Result struct {
	Summary         *stats.Summary
	Findings        []findings.Finding
	Matches         []ctevent.Record
	ObjectsScanned  int
	RecordsRead     int
	MatchedRecords  int
	DroppedFindings int
	// MaxSeverity is the highest severity of every finding the scan hit,
	// including ones dropped past the findings cap. It is only meaningful
	// when HasFindings is true.
	MaxSeverity findings.Severity
	// HasFindings is true when at least one rule fired, even if every hit
	// was later discarded because the findings cap was full.
	HasFindings bool
	// SeverityCounts is the number of rule hits per severity, including hits
	// dropped past the findings cap.
	SeverityCounts map[findings.Severity]int
	Errors         []string
	// ReadKeys lists, sorted, every object whose records were read.
	ReadKeys []string
	Elapsed  time.Duration
}

// shard is one fetch worker's private accumulator. Because nothing is shared
// while the scan runs, there is no lock on the per-record path.
type shard struct {
	summary        *stats.Summary
	detector       *findings.Detector
	matches        []ctevent.Record
	matchedRecords int
	emit           func(ctevent.Record)
}

// Run scans the scope and returns the aggregated result. Errors reading an
// individual object are collected into Result.Errors rather than aborting the
// scan; only setup failures and context cancellation return an error.
func Run(ctx context.Context, store s3src.ObjectStore, opts Options) (Result, error) {
	started := time.Now()

	prefixes := opts.Scope.Prefixes()
	if len(prefixes) == 0 {
		return Result{}, errors.New("empty scan scope: need at least one account, one region, and a valid date range")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}
	rules := opts.Rules
	if rules == nil {
		rules = findings.DefaultRules()
	}

	out, err := scan(ctx, store, scanSpec[ctevent.Record, *shard]{
		prefixes:     prefixes,
		listWorkers:  opts.ListWorkers,
		fetchWorkers: opts.FetchWorkers,
		keep:         s3src.IsCloudTrailLogKey,
		skip:         opts.Skip,
		decode: func(_ string, r io.Reader) ([]ctevent.Record, error) {
			return ctevent.DecodeGzip(r)
		},
		newShard: func() *shard {
			det := findings.NewDetector(rules)
			det.Max = opts.FindingsCap
			sh := &shard{summary: stats.NewSummary(), detector: det}
			if opts.Emit != nil {
				sh.emit = opts.Emit()
			}
			return sh
		},
		log: opts.Debug,
		visit: func(sh *shard, rec ctevent.Record) bool {
			if !opts.Filter.Match(rec) {
				return false
			}
			sh.matchedRecords++
			if sh.emit != nil {
				sh.emit(rec)
			}
			sh.summary.Add(rec)
			sh.detector.Inspect(rec)
			if len(sh.matches) < maxEvents {
				sh.matches = append(sh.matches, rec)
			}
			return true
		},
	})
	if err != nil {
		return Result{}, err
	}

	// Merge stage: exactly once, after every worker has finished.
	res := Result{
		Summary:        stats.NewSummary(),
		ObjectsScanned: out.objectsScanned,
		RecordsRead:    out.recordsRead,
		Errors:         out.errs,
		ReadKeys:       out.readKeys,
	}
	merged := findings.NewDetector(rules)
	merged.Max = opts.FindingsCap
	for _, sh := range out.shards {
		res.Summary.Merge(sh.summary)
		merged.Merge(sh.detector)
		res.MatchedRecords += sh.matchedRecords
		for _, m := range sh.matches {
			if len(res.Matches) >= maxEvents {
				break
			}
			res.Matches = append(res.Matches, m)
		}
	}
	res.Findings = merged.Findings()
	res.DroppedFindings = merged.Dropped
	res.MaxSeverity = merged.MaxSeverity
	res.HasFindings = merged.Seen
	res.SeverityCounts = merged.Counts

	sort.SliceStable(res.Matches, func(i, j int) bool {
		return res.Matches[i].EventTime.Before(res.Matches[j].EventTime)
	})

	res.Elapsed = time.Since(started)
	return res, nil
}
