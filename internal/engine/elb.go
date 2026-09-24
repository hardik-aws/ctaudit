package engine

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/s3src"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// ELBOptions configures one load balancer access log scan.
type ELBOptions struct {
	// Scope selects accounts, regions, and days. Its Service is forced to
	// s3src.ServiceELB.
	Scope  s3src.Scope
	Filter elblog.Filter
	// LBs keeps only objects whose load balancer name contains one of these
	// substrings (case-insensitive). Empty keeps every load balancer.
	LBs []string
	// Kinds keeps only these load balancer kinds. Empty keeps all.
	Kinds        []elblog.Kind
	ListWorkers  int
	FetchWorkers int
	// MaxEvents caps how many matching entries are retained for the request
	// table. Statistics are unaffected.
	MaxEvents int
	// Emit, when set, is called once per fetch worker. The function it
	// returns receives every request and connection that passes the
	// filter, uncapped by MaxEvents, from that worker's goroutine only.
	Emit func() func(elblog.Entry)
	// Skip, when set, leaves out every object whose key it returns true for.
	// It is called from the list workers and must be safe for concurrent use.
	Skip func(key string) bool
	// Debug, when set, receives one line per listed prefix and per object.
	Debug *slog.Logger
}

// ELBResult is everything the load balancer report needs.
type ELBResult struct {
	Summary        *stats.ELBSummary
	Matches        []elblog.Entry
	ObjectsScanned int
	RecordsRead    int
	MatchedRecords int
	// Conns summarises ALB connection log records (conn_log_* objects).
	// They are counted separately so they never inflate request totals.
	Conns *stats.ConnSummary
	// ConnMatches holds the earliest MaxEvents matching connections.
	ConnMatches  []elblog.Entry
	ConnsRead    int
	MatchedConns int
	Errors       []string
	// ReadKeys lists, sorted, every object whose records were read.
	ReadKeys []string
	Elapsed  time.Duration
}

type elbShard struct {
	summary        *stats.ELBSummary
	matches        []elblog.Entry
	matchedRecords int
	conns          *stats.ConnSummary
	connMatches    []elblog.Entry
	connsRead      int
	matchedConns   int
	emit           func(elblog.Entry)
}

// RunELB scans ELB access logs in the scope and returns the aggregated
// result. Like Run, per-object errors (including unparseable lines) are
// collected into ELBResult.Errors rather than aborting the scan.
func RunELB(ctx context.Context, store s3src.ObjectStore, opts ELBOptions) (ELBResult, error) {
	started := time.Now()

	scope := opts.Scope
	scope.Service = s3src.ServiceELB
	prefixes := scope.Prefixes()
	if len(prefixes) == 0 {
		return ELBResult{}, errors.New("empty scan scope: need at least one account, one region, and a valid date range")
	}
	if err := ctx.Err(); err != nil {
		return ELBResult{}, err
	}

	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}

	out, err := scan(ctx, store, scanSpec[elblog.Entry, *elbShard]{
		prefixes:     prefixes,
		listWorkers:  opts.ListWorkers,
		fetchWorkers: opts.FetchWorkers,
		keep:         elbKeyFilter(opts.LBs, opts.Kinds),
		skip:         opts.Skip,
		decode:       elblog.Decode,
		newShard: func() *elbShard {
			sh := &elbShard{summary: stats.NewELBSummary(), conns: stats.NewConnSummary()}
			if opts.Emit != nil {
				sh.emit = opts.Emit()
			}
			return sh
		},
		log: opts.Debug,
		visit: func(sh *elbShard, e elblog.Entry) bool {
			if e.Conn {
				sh.connsRead++
				if !opts.Filter.MatchConn(e) {
					return false
				}
				sh.matchedConns++
				if sh.emit != nil {
					sh.emit(e)
				}
				sh.conns.Add(e)
				sh.connMatches = append(sh.connMatches, e)
				if len(sh.connMatches) >= 2*maxEvents {
					sh.connMatches = earliest(sh.connMatches, maxEvents)
				}
				return true
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
			// Keep each shard's earliest maxEvents entries. Trimming at 2x
			// amortises the sort so the per-entry cost stays constant.
			if len(sh.matches) >= 2*maxEvents {
				sh.matches = earliest(sh.matches, maxEvents)
			}
			return true
		},
	})
	if err != nil {
		return ELBResult{}, err
	}

	res := ELBResult{
		Summary:        stats.NewELBSummary(),
		Conns:          stats.NewConnSummary(),
		ObjectsScanned: out.objectsScanned,
		Errors:         out.errs,
		ReadKeys:       out.readKeys,
	}
	for _, sh := range out.shards {
		res.Summary.Merge(sh.summary)
		res.MatchedRecords += sh.matchedRecords
		res.Matches = append(res.Matches, sh.matches...)
		res.Conns.Merge(sh.conns)
		res.ConnsRead += sh.connsRead
		res.MatchedConns += sh.matchedConns
		res.ConnMatches = append(res.ConnMatches, sh.connMatches...)
	}
	res.RecordsRead = out.recordsRead - res.ConnsRead
	res.Matches = earliest(res.Matches, maxEvents)
	res.ConnMatches = earliest(res.ConnMatches, maxEvents)

	res.Elapsed = time.Since(started)
	return res, nil
}

// earliest sorts entries by time and keeps at most n of them.
func earliest(entries []elblog.Entry, n int) []elblog.Entry {
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Time.Before(entries[j].Time)
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// elbKeyFilter builds the keep function: only ELB log objects, optionally
// restricted by load balancer name and kind.
func elbKeyFilter(lbs []string, kinds []elblog.Kind) func(string) bool {
	lower := make([]string, 0, len(lbs))
	for _, lb := range lbs {
		if lb = strings.ToLower(strings.TrimSpace(lb)); lb != "" {
			lower = append(lower, lb)
		}
	}
	return func(key string) bool {
		if !elblog.IsLogKey(key) {
			return false
		}
		if len(kinds) > 0 {
			k := elblog.KindFromKey(key)
			found := false
			for _, want := range kinds {
				if k == want {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		if len(lower) > 0 {
			name := strings.ToLower(elblog.LBNameFromKey(key))
			for _, lb := range lower {
				if strings.Contains(name, lb) {
					return true
				}
			}
			return false
		}
		return true
	}
}
