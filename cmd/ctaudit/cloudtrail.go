package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/query"
	"github.com/gsmappdev/ctaudit/internal/report"
)

// config is the parsed cloudtrail command line.
type config struct {
	Store    storeConfig
	HTMLPath string
	PDFPath  string
	TopN     int
	// FailOn is nil when --fail-on is "none".
	FailOn  *findings.Severity
	Opts    engine.Options
	Meta    report.Meta
	Observe observeFlags
	Log     logFlags
}

func runCloudTrail(ctx context.Context, args []string, stdout, stderr io.Writer, newStore storeFactory, now time.Time) int {
	cfg, err := parseArgsTo(args, now, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}

	log := cfg.Log.logger(stderr)
	cfg.Opts.Debug, cfg.Store.Log, cfg.Observe.log = log, log, log
	debugScope(log, "cloudtrail", cfg.Store, cfg.Opts.Scope, cfg.Opts.Filter.Since, cfg.Opts.Filter.Until, cfg.Opts.ListWorkers, cfg.Opts.FetchWorkers)

	// Sinks are built before any S3 call so a bad URL or credential fails
	// fast.
	obs, err := newObserver("cloudtrail", cfg.Observe, now)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}
	defer obs.abort()
	cfg.Opts.Emit = obs.eventEmit()

	store, err := newStore(ctx, cfg.Store)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}

	res, err := engine.Run(ctx, store, cfg.Opts)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: scan failed: %v\n", err)
		return exitFailed
	}
	cfg.Meta.GeneratedAt = time.Now().UTC()
	debugLog(log, "scan done", "objects", res.ObjectsScanned, "records", res.RecordsRead, "matched", res.MatchedRecords,
		"findings", len(res.Findings), "errors", len(res.Errors), "dur", res.Elapsed)
	warnIfEmpty(stderr, res.ObjectsScanned, cfg.Opts.Scope)

	if err := report.Terminal(stdout, res, cfg.Meta, cfg.TopN); err != nil {
		fmt.Fprintf(stderr, "ctaudit: write summary: %v\n", err)
		return exitFailed
	}
	if cfg.HTMLPath != "" {
		err := writeFile(cfg.HTMLPath, func(w io.Writer) error { return report.HTML(w, res, cfg.Meta, cfg.TopN) })
		if err != nil {
			fmt.Fprintf(stderr, "ctaudit: %v\n", err)
			return exitFailed
		}
		fmt.Fprintf(stdout, "\nHTML report written to %s\n", cfg.HTMLPath)
	}
	if cfg.PDFPath != "" {
		err := writeFile(cfg.PDFPath, func(w io.Writer) error { return report.PDF(w, res, cfg.Meta, cfg.TopN) })
		if err != nil {
			fmt.Fprintf(stderr, "ctaudit: %v\n", err)
			return exitFailed
		}
		fmt.Fprintf(stdout, "PDF report written to %s\n", cfg.PDFPath)
	}
	// A failed push fails the run, like an unreadable object.
	common := commonMetrics{
		objects: res.ObjectsScanned,
		read:    res.RecordsRead,
		matched: res.MatchedRecords,
		errors:  len(res.Errors),
		elapsed: res.Elapsed,
	}
	if !obs.finish(ctx, stderr, res.Findings, common, cloudTrailMetrics(res)) {
		return exitFailed
	}

	// Unreadable objects mean the report may be incomplete, which matters more
	// than any finding: a CI gate must not pass on a partial scan.
	if len(res.Errors) > 0 {
		return exitFailed
	}
	if shouldFailOn(res, cfg.FailOn) {
		return exitFindings
	}
	return exitOK
}

// shouldFailOn reports whether --fail-on should turn a scan's findings into a
// non-zero exit. HasFindings distinguishes "no findings at all" from a
// finding that was discarded once the findings cap filled up: MaxSeverity
// still reflects it, so a dropped CRITICAL finding cannot slip past
// --fail-on critical just because Findings() no longer contains it.
func shouldFailOn(res engine.Result, failOn *findings.Severity) bool {
	return failOn != nil && res.HasFindings && res.MaxSeverity >= *failOn
}

// parseArgs parses the cloudtrail flags, discarding usage output.
func parseArgs(args []string, now time.Time) (config, error) {
	return parseArgsTo(args, now, io.Discard)
}

func parseArgsTo(args []string, now time.Time, usage io.Writer) (config, error) {
	cfg, _, err := parseArgsFlags(args, now, usage, nil)
	return cfg, err
}

// parseArgsFlags parses the flags and also reports which flags were set on the
// command line. extra, when not nil, registers additional flags first.
func parseArgsFlags(args []string, now time.Time, usage io.Writer, extra func(*flag.FlagSet)) (config, map[string]bool, error) {
	fs := flag.NewFlagSet("ctaudit cloudtrail", flag.ContinueOnError)
	fs.SetOutput(usage)

	var (
		cfg             config
		common          commonFlags
		events, sources string
		failOn          string
		f               query.Filter
	)

	common.register(fs, now, "CloudTrail log bucket (required)", "key prefix the trail writes under, before AWSLogs/")
	fs.StringVar(&cfg.Opts.Scope.OrgID, "org-id", "", "AWS Organizations ID for an organization trail, e.g. o-abc123")
	fs.StringVar(&f.Principal, "principal", "", "only events whose actor contains this text")
	fs.StringVar(&f.Resource, "resource", "", "only events whose resource ARN or request parameters contain this text")
	fs.StringVar(&f.SourceIP, "source-ip", "", "only events whose source IP contains this text")
	fs.StringVar(&events, "event", "", "comma-separated event names, e.g. DeleteBucket,PutBucketPolicy")
	fs.StringVar(&sources, "source", "", "comma-separated event sources, e.g. s3.amazonaws.com or s3")
	fs.BoolVar(&f.ErrorsOnly, "errors-only", false, "only events that returned an error code")
	fs.BoolVar(&f.WritesOnly, "writes-only", false, "only mutating (non-read-only) events")
	fs.StringVar(&cfg.HTMLPath, "html", "ctaudit-report.html", `HTML report path; "" to skip`)
	fs.StringVar(&cfg.PDFPath, "pdf", "", "also write a printable PDF report to this .pdf path")
	fs.IntVar(&cfg.Opts.MaxEvents, "max-events", 200, "matching events kept for the events table")
	fs.StringVar(&failOn, "fail-on", "none", "exit 1 when a finding is at or above this severity: none, low, medium, high, critical")

	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return config{}, nil, err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	scope, err := common.resolve(fs)
	if err != nil {
		return config{}, nil, err
	}
	if cfg.Opts.MaxEvents < 1 {
		return config{}, nil, errors.New("--max-events must be at least 1")
	}
	if err := checkHTMLPath(cfg.HTMLPath); err != nil {
		return config{}, nil, err
	}
	if err := checkPDFPath(cfg.PDFPath); err != nil {
		return config{}, nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(failOn), "none") {
		sev, err := findings.ParseSeverity(failOn)
		if err != nil {
			return config{}, nil, fmt.Errorf("--fail-on: %w", err)
		}
		cfg.FailOn = &sev
	}

	cfg.Store = common.store
	cfg.TopN = common.topN
	cfg.Observe = common.obs
	cfg.Log = common.log
	cfg.Opts.ListWorkers = common.listWorkers
	cfg.Opts.FetchWorkers = common.fetchWorkers
	cfg.Opts.Scope.BasePrefix = common.prefix
	cfg.Opts.Scope.Accounts = scope.accounts
	cfg.Opts.Scope.Regions = scope.regions

	// CloudTrail files an object under the day it was delivered, not the day
	// of the events inside it, so events from late on --until can land in the
	// next day's prefix. Scan that extra day and let the filter trim to the
	// exact window: Filter.Until is exclusive.
	dayAfter := scope.end.AddDate(0, 0, 1)
	cfg.Opts.Scope.Start = scope.start
	cfg.Opts.Scope.End = dayAfter
	f.Events = splitList(events)
	f.Sources = splitList(sources)
	f.Since = scope.start
	f.Until = dayAfter
	cfg.Opts.Filter = f

	cfg.Meta = report.Meta{
		Bucket:   cfg.Store.Bucket,
		Accounts: scope.accounts,
		Regions:  scope.regions,
		Since:    scope.start,
		Until:    scope.end,
		Narrowed: f.IsNarrowing(),
	}
	return cfg, set, nil
}
