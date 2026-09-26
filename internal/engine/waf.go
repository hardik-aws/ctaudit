package engine

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/s3src"
	"github.com/gsmappdev/ctaudit/internal/stats"
	"github.com/gsmappdev/ctaudit/internal/waflog"
	"github.com/gsmappdev/ctaudit/internal/wafrules"
)

// WAFOptions configures one AWS WAF log scan.
type WAFOptions struct {
	// Scope selects accounts, regions, and days. Its Service is forced to
	// s3src.ServiceWAF.
	Scope s3src.Scope
	// WebACLs keeps only ACLs whose name contains one of these substrings
	// (case-insensitive). Empty keeps every discovered ACL.
	WebACLs []string
	Filter  waflog.Filter
	// BlockThreshold is passed through to wafrules.Detect.
	BlockThreshold int
	ListWorkers    int
	FetchWorkers   int
	// MaxEvents caps how many matching entries are retained for the request
	// table. Statistics are unaffected.
	MaxEvents int
	// Emit, when set, is called once per fetch worker. The function it
	// returns receives every request that passes the filter, uncapped by
	// MaxEvents, from that worker's goroutine only.
	Emit func() func(waflog.Entry)
	// Skip, when set, leaves out every object whose key it returns true for.
	// It is called from the list workers and must be safe for concurrent use.
	Skip func(key string) bool
	// Debug, when set, receives one line per listed prefix and per object.
	Debug *slog.Logger
}

// WAFResult is everything the WAF report needs.
type WAFResult struct {
	Summary         *stats.WAFSummary
	Findings        []findings.Finding
	FindingsDropped int
	Matches         []waflog.Entry
	// WebACLs lists, sorted, every web ACL name that was discovered and
	// kept by WAFOptions.WebACLs.
	WebACLs        []string
	ObjectsScanned int
	RecordsRead    int
	MatchedRecords int
	Errors         []string
	// ReadKeys lists, sorted, every object whose records were read.
	ReadKeys []string
	Elapsed  time.Duration
}

type wafShard struct {
	summary        *stats.WAFSummary
	matches        []waflog.Entry
	matchedRecords int
	emit           func(waflog.Entry)
}

// RunWAF discovers the web ACLs in scope, scans their logs, and returns the
// aggregated result with findings. Per-object errors are collected into
// WAFResult.Errors rather than aborting the scan; a failed ACL discovery
// listing aborts it, because the scope would silently shrink.
func RunWAF(ctx context.Context, store s3src.ObjectStore, opts WAFOptions) (WAFResult, error) {
	started := time.Now()

	scope := opts.Scope
	scope.Service = s3src.ServiceWAF
	if len(scope.Accounts) == 0 || len(scope.Regions) == 0 || scope.End.Before(scope.Start) {
		return WAFResult{}, errors.New("empty scan scope: need at least one account, one region, and a valid date range")
	}
	if err := ctx.Err(); err != nil {
		return WAFResult{}, err
	}

	prefixes, acls, err := scope.WAFPrefixes(ctx, store, opts.WebACLs)
	if err != nil {
		return WAFResult{}, err
	}
	if opts.Debug != nil {
		opts.Debug.Debug("web ACLs discovered", "count", len(acls), "prefixes", len(prefixes))
	}

	res := WAFResult{Summary: stats.NewWAFSummary(), WebACLs: acls}
	if len(prefixes) == 0 {
		res.Elapsed = time.Since(started)
		return res, nil
	}

	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}

	out, err := scan(ctx, store, scanSpec[waflog.Entry, *wafShard]{
		prefixes:     prefixes,
		listWorkers:  opts.ListWorkers,
		fetchWorkers: opts.FetchWorkers,
		keep:         waflog.IsLogKey,
		skip:         opts.Skip,
		decode:       waflog.Decode,
		newShard: func() *wafShard {
			sh := &wafShard{summary: stats.NewWAFSummary()}
			if opts.Emit != nil {
				sh.emit = opts.Emit()
			}
			return sh
		},
		log: opts.Debug,
		visit: func(sh *wafShard, e waflog.Entry) bool {
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
				sh.matches = earliestWAF(sh.matches, maxEvents)
			}
			return true
		},
	})
	if err != nil {
		return WAFResult{}, err
	}

	res.ObjectsScanned, res.RecordsRead, res.Errors, res.ReadKeys = out.objectsScanned, out.recordsRead, out.errs, out.readKeys
	for _, sh := range out.shards {
		res.Summary.Merge(sh.summary)
		res.MatchedRecords += sh.matchedRecords
		res.Matches = append(res.Matches, sh.matches...)
	}
	res.Matches = earliestWAF(res.Matches, maxEvents)
	res.Findings, res.FindingsDropped = wafrules.Detect(res.Summary, wafrules.Options{BlockThreshold: opts.BlockThreshold})

	res.Elapsed = time.Since(started)
	return res, nil
}

// earliestWAF sorts entries by time and keeps at most n of them.
func earliestWAF(entries []waflog.Entry, n int) []waflog.Entry {
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Time.Before(entries[j].Time) })
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}
