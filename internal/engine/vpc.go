package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync/atomic"
	"time"

	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/flowlog"
	"github.com/gsmappdev/ctaudit/internal/s3src"
	"github.com/gsmappdev/ctaudit/internal/stats"
	"github.com/gsmappdev/ctaudit/internal/vpcrules"
)

// ErrHiveLayout means the scope held no flow logs but the bucket has flow
// logs written with Hive-compatible S3 prefixes, which ctaudit does not read.
var ErrHiveLayout = errors.New("flow logs use Hive-compatible S3 prefixes, which ctaudit does not read; create the flow log without Hive-compatible prefixes (text format, default partitioning)")

// VPCOptions configures one VPC Flow Logs scan.
type VPCOptions struct {
	// Scope selects accounts, regions, and days. Its Service is forced to
	// s3src.ServiceVPC.
	Scope  s3src.Scope
	Filter flowlog.Filter
	// Rules tunes the findings; its thresholds also size the summary's
	// distinct trackers.
	Rules        vpcrules.Options
	ListWorkers  int
	FetchWorkers int
	// MaxEvents caps how many matching flows are retained for the flow
	// table. Statistics are unaffected.
	MaxEvents int
	// Emit, when set, is called once per fetch worker. The function it
	// returns receives every flow that passes the filter, uncapped by
	// MaxEvents, from that worker's goroutine only. NODATA and SKIPDATA rows
	// are never emitted.
	Emit func() func(flowlog.Entry)
	// Skip, when set, leaves out every object whose key it returns true for.
	// It is called from the list workers and must be safe for concurrent use.
	Skip func(key string) bool
	// Debug, when set, receives one line per listed prefix and per object.
	Debug *slog.Logger
}

// VPCResult is everything the VPC report needs.
type VPCResult struct {
	Summary         *stats.VPCSummary
	Findings        []findings.Finding
	FindingsDropped int
	Matches         []flowlog.Entry
	ObjectsScanned  int
	// RecordsRead counts every decoded record, status rows included.
	RecordsRead    int
	MatchedRecords int
	Errors         []string
	// ReadKeys lists, sorted, every object whose records were read.
	ReadKeys []string
	Elapsed  time.Duration
}

type vpcShard struct {
	summary        *stats.VPCSummary
	matches        []flowlog.Entry
	matchedRecords int
	emit           func(flowlog.Entry)
}

// RunVPC scans the flow logs in scope and returns the aggregated result with
// findings. Objects are streamed, so memory is bounded by the summary caps
// and MaxEvents, not by object size. Per-object errors, Parquet objects
// included, are collected into VPCResult.Errors rather than aborting the
// scan.
func RunVPC(ctx context.Context, store s3src.ObjectStore, opts VPCOptions) (VPCResult, error) {
	started := time.Now()

	scope := opts.Scope
	scope.Service = s3src.ServiceVPC
	if len(scope.Accounts) == 0 || len(scope.Regions) == 0 || scope.End.Before(scope.Start) {
		return VPCResult{}, errors.New("empty scan scope: need at least one account, one region, and a valid date range")
	}
	if err := ctx.Err(); err != nil {
		return VPCResult{}, err
	}

	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}
	limits := opts.Rules.Limits()

	// keysKept counts every key the skip hook was asked about, i.e. every
	// object IsLogKey kept, whether or not Skip then dropped it. In serve
	// mode a tick where every one of those keys was already seen has
	// ObjectsScanned == 0 just like a bucket with no flow logs at all, so
	// ObjectsScanned alone cannot tell the two apart. keysKept can: it stays
	// at 0 only when the scope truly held no flow log objects, which is the
	// only time the Hive-layout probe below should run.
	var keysKept int64
	skip := func(key string) bool {
		atomic.AddInt64(&keysKept, 1)
		if opts.Skip != nil {
			return opts.Skip(key)
		}
		return false
	}

	out, err := scan(ctx, store, scanSpec[flowlog.Entry, *vpcShard]{
		prefixes:     scope.Prefixes(),
		listWorkers:  opts.ListWorkers,
		fetchWorkers: opts.FetchWorkers,
		keep:         flowlog.IsLogKey,
		skip:         skip,
		stream:       flowlog.Stream,
		newShard: func() *vpcShard {
			sh := &vpcShard{summary: stats.NewVPCSummary(limits)}
			if opts.Emit != nil {
				sh.emit = opts.Emit()
			}
			return sh
		},
		log: opts.Debug,
		visit: func(sh *vpcShard, e flowlog.Entry) bool {
			// A missing log-status column means every row is a flow.
			if e.LogStatus != "" && e.LogStatus != flowlog.StatusOK {
				if opts.Filter.InWindow(e) {
					sh.summary.AddStatus(e.LogStatus)
				}
				return false
			}
			if !opts.Filter.Match(e) {
				return false
			}
			sh.matchedRecords++
			if sh.emit != nil {
				sh.emit(e)
			}
			sh.summary.Add(e)
			sh.matches = append(sh.matches, e)
			if len(sh.matches) >= 2*maxEvents {
				sh.matches = earliestVPC(sh.matches, maxEvents)
			}
			return true
		},
	})
	if err != nil {
		return VPCResult{}, err
	}

	res := VPCResult{
		Summary:        stats.NewVPCSummary(limits),
		ObjectsScanned: out.objectsScanned,
		RecordsRead:    out.recordsRead,
		Errors:         out.errs,
		ReadKeys:       out.readKeys,
	}
	for _, sh := range out.shards {
		res.Summary.Merge(sh.summary)
		res.MatchedRecords += sh.matchedRecords
		res.Matches = append(res.Matches, sh.matches...)
	}
	res.Matches = earliestVPC(res.Matches, maxEvents)

	if atomic.LoadInt64(&keysKept) == 0 && len(res.Errors) == 0 {
		prefix, err := hivePrefixWithObjects(ctx, store, scope)
		if err != nil {
			return VPCResult{}, err
		}
		if prefix != "" {
			return VPCResult{}, fmt.Errorf("%w (found objects under %s)", ErrHiveLayout, prefix)
		}
	}

	res.Findings, res.FindingsDropped = vpcrules.Detect(res.Summary, opts.Rules)
	res.Elapsed = time.Since(started)
	return res, nil
}

// hivePrefixWithObjects lists one page of each account and region's Hive
// prefix and returns the first that holds objects, or "". It runs only
// after a scan found no flow log objects at all, to turn a silent empty
// report into a clear error.
func hivePrefixWithObjects(ctx context.Context, store s3src.ObjectStore, scope s3src.Scope) (string, error) {
	for _, acct := range scope.Accounts {
		for _, region := range scope.Regions {
			p := scope.VPCHivePrefix(acct, region)
			keys, _, err := store.ListPage(ctx, p, "")
			if err != nil {
				return "", fmt.Errorf("list %s: %w", p, err)
			}
			if len(keys) > 0 {
				return p, nil
			}
		}
	}
	return "", nil
}

// earliestVPC sorts flows by start and keeps at most n of them.
func earliestVPC(entries []flowlog.Entry, n int) []flowlog.Entry {
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Start.Before(entries[j].Start) })
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}
