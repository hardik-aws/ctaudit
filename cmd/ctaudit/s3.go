package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/report"
	"github.com/gsmappdev/ctaudit/internal/s3log"
	"github.com/gsmappdev/ctaudit/internal/s3rules"
	"github.com/gsmappdev/ctaudit/internal/s3src"
)

// s3StatusPattern accepts an HTTP status code or class for --status.
var s3StatusPattern = regexp.MustCompile(`^([1-5]\d\d|[1-5]xx)$`)

// s3Config is the parsed s3 command line.
type s3Config struct {
	Store    storeConfig
	HTMLPath string
	PDFPath  string
	TopN     int
	FailOn   findings.Severity
	// FailOff is true when --fail-on is "none".
	FailOff bool
	Opts    engine.S3Options
	Meta    report.Meta
	Observe observeFlags
	Log     logFlags
}

func runS3(ctx context.Context, args []string, stdout, stderr io.Writer, newStore storeFactory, now time.Time) int {
	cfg, _, err := parseS3ArgsFlags(args, now, stderr, nil)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}

	log := cfg.Log.logger(stderr)
	cfg.Opts.Debug, cfg.Store.Log, cfg.Observe.log = log, log, log
	debugLog(log, "scan scope", "subcommand", "s3", "bucket", cfg.Store.Bucket, "bucket_region", cfg.Store.BucketRegion,
		"layout", cfg.Opts.Layout, "accounts", strings.Join(cfg.Opts.Scope.Accounts, ","), "regions", strings.Join(cfg.Opts.Scope.Regions, ","),
		"scope_start", cfg.Opts.Scope.Start.Format(dayLayout), "scope_end", cfg.Opts.Scope.End.Format(dayLayout),
		"since", cfg.Opts.Filter.Since, "until", cfg.Opts.Filter.Until,
		"list_workers", cfg.Opts.ListWorkers, "fetch_workers", cfg.Opts.FetchWorkers)

	// Sinks are built before any S3 call so a bad URL or credential fails
	// fast.
	obs, err := newObserver("s3", cfg.Observe, now)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}
	defer obs.abort()
	cfg.Opts.Emit = obs.s3Emit()

	store, err := newStore(ctx, cfg.Store)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}

	res, err := engine.RunS3(ctx, store, cfg.Opts)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: scan failed: %v\n", err)
		return exitFailed
	}
	cfg.Meta.GeneratedAt = time.Now().UTC()
	debugLog(log, "scan done", "objects", res.ObjectsScanned, "records", res.RecordsRead, "matched", res.MatchedRecords,
		"findings", len(res.Findings), "source_buckets", len(res.SourceBuckets), "errors", len(res.Errors), "dur", res.Elapsed)
	if res.ObjectsScanned == 0 {
		example := ""
		if res.FirstPrefix != "" {
			example = fmt.Sprintf(" (e.g. s3://%s/%s)", cfg.Store.Bucket, res.FirstPrefix)
		}
		fmt.Fprintf(stderr, "ctaudit: warning: no S3 access log objects found under %d prefixes%s; check --bucket, --prefix, --layout, and the dates\n",
			res.Prefixes, example)
	}
	if cfg.Opts.Layout == s3src.S3LayoutPartitioned && len(res.SourceBuckets) == 0 {
		fmt.Fprintln(stderr, "ctaudit: warning: no source buckets found under <prefix><account>/<region>/ for the given accounts and regions")
	}

	if err := report.S3Terminal(stdout, res, cfg.Meta, cfg.TopN); err != nil {
		fmt.Fprintf(stderr, "ctaudit: write summary: %v\n", err)
		return exitFailed
	}
	if cfg.HTMLPath != "" {
		err := writeFile(cfg.HTMLPath, func(w io.Writer) error { return report.S3HTML(w, res, cfg.Meta, cfg.TopN) })
		if err != nil {
			fmt.Fprintf(stderr, "ctaudit: %v\n", err)
			return exitFailed
		}
		fmt.Fprintf(stdout, "\nHTML report written to %s\n", cfg.HTMLPath)
	}
	if cfg.PDFPath != "" {
		err := writeFile(cfg.PDFPath, func(w io.Writer) error { return report.S3PDF(w, res, cfg.Meta, cfg.TopN) })
		if err != nil {
			fmt.Fprintf(stderr, "ctaudit: %v\n", err)
			return exitFailed
		}
		fmt.Fprintf(stdout, "PDF report written to %s\n", cfg.PDFPath)
	}
	common := commonMetrics{
		objects: res.ObjectsScanned,
		read:    res.RecordsRead,
		matched: res.MatchedRecords,
		errors:  len(res.Errors),
		elapsed: res.Elapsed,
	}
	if !obs.finish(ctx, stderr, res.Findings, common, s3Metrics(res)) {
		return exitFailed
	}

	// As for the other subcommands, a partial scan must not look clean.
	if len(res.Errors) > 0 {
		return exitFailed
	}
	if sev, ok := s3rules.MaxSeverity(res.Findings); ok && !cfg.FailOff && sev >= cfg.FailOn {
		return exitFindings
	}
	return exitOK
}

// parseS3ArgsFlags parses the flags and also reports which flags were set on
// the command line. extra, when not nil, registers additional flags first, so
// serve can reuse this for its own flag set.
func parseS3ArgsFlags(args []string, now time.Time, usage io.Writer, extra func(*flag.FlagSet)) (s3Config, map[string]bool, error) {
	fs := flag.NewFlagSet("ctaudit s3", flag.ContinueOnError)
	fs.SetOutput(usage)

	var (
		cfg             s3Config
		common          commonFlags
		layout          string
		sourceBuckets   string
		operations      string
		statuses        string
		failOn          string
		deniedThreshold int
		deleteThreshold int
		egressBytes     int64
		f               s3log.Filter
	)

	common.register(fs, now, "S3 server access log target bucket (required)",
		`target prefix configured for server access logging, used verbatim (include any trailing "/")`)
	fs.Lookup("accounts").Usage = "comma-separated 12-digit source account IDs (partitioned layout only)"
	fs.Lookup("regions").Usage = "comma-separated source bucket regions (partitioned layout only)"
	fs.StringVar(&layout, "layout", s3src.S3LayoutSimple, "log object key format: simple or partitioned")
	fs.StringVar(&sourceBuckets, "source-buckets", "", "comma-separated source bucket names; a record is kept if its bucket contains any of them")
	fs.StringVar(&operations, "operations", "", "comma-separated operations, matched as substrings, e.g. REST.PUT.OBJECT or DELETE")
	fs.StringVar(&statuses, "status", "", "comma-separated HTTP status codes or classes, e.g. 403,5xx")
	fs.StringVar(&f.Requester, "requester", "", `only requests whose requester contains this text; "anonymous" for unauthenticated`)
	fs.StringVar(&f.ClientIP, "client-ip", "", "only requests whose remote IP contains this text")
	fs.StringVar(&f.KeyPrefix, "key-prefix", "", "only requests whose object key starts with this text")
	fs.BoolVar(&f.ErrorsOnly, "errors-only", false, "only requests with status 400 or higher or an error code")
	fs.IntVar(&deniedThreshold, "denied-threshold", 100, "denied requests from one IP or requester that become a finding")
	fs.IntVar(&deleteThreshold, "delete-threshold", 1000, "objects deleted by one requester that become a finding")
	fs.Int64Var(&egressBytes, "egress-threshold", 10<<30, "bytes sent to one requester or IP that become a finding")
	fs.StringVar(&failOn, "fail-on", "critical", "exit 1 when a finding is at or above this severity: none, low, medium, high, critical")
	fs.StringVar(&cfg.HTMLPath, "html", "s3-report.html", `HTML report path; "" to skip`)
	fs.StringVar(&cfg.PDFPath, "pdf", "", "also write a printable PDF report to this .pdf path")
	fs.IntVar(&cfg.Opts.MaxEvents, "max-events", 200, "matching requests kept for the requests table (earliest first)")

	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return s3Config{}, nil, err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	switch layout {
	case s3src.S3LayoutSimple, s3src.S3LayoutPartitioned:
	default:
		return s3Config{}, nil, fmt.Errorf("--layout: %q is not %s or %s", layout, s3src.S3LayoutSimple, s3src.S3LayoutPartitioned)
	}
	// The simple layout has no account or region in its keys, so the flags
	// are accepted (the Helm chart always passes them) but not required.
	common.scopeOptional = layout == s3src.S3LayoutSimple
	scope, err := common.resolve(fs)
	if err != nil {
		return s3Config{}, nil, err
	}
	if cfg.Opts.MaxEvents < 1 {
		return s3Config{}, nil, errors.New("--max-events must be at least 1")
	}
	if deniedThreshold <= 0 {
		return s3Config{}, nil, errors.New("--denied-threshold must be greater than 0")
	}
	if deleteThreshold <= 0 {
		return s3Config{}, nil, errors.New("--delete-threshold must be greater than 0")
	}
	if egressBytes <= 0 {
		return s3Config{}, nil, errors.New("--egress-threshold must be greater than 0")
	}
	if err := checkHTMLPath(cfg.HTMLPath); err != nil {
		return s3Config{}, nil, err
	}
	if err := checkPDFPath(cfg.PDFPath); err != nil {
		return s3Config{}, nil, err
	}
	for _, s := range splitList(statuses) {
		s = strings.ToLower(s)
		if !s3StatusPattern.MatchString(s) {
			return s3Config{}, nil, fmt.Errorf("--status: %q is not a status code (403) or class (4xx)", s)
		}
		f.Statuses = append(f.Statuses, s)
	}
	if strings.EqualFold(strings.TrimSpace(failOn), "none") {
		cfg.FailOff = true
	} else {
		sev, err := findings.ParseSeverity(failOn)
		if err != nil {
			return s3Config{}, nil, fmt.Errorf("--fail-on: %w", err)
		}
		cfg.FailOn = sev
	}

	cfg.Store = common.store
	cfg.TopN = common.topN
	cfg.Observe = common.obs
	cfg.Log = common.log
	cfg.Opts.Layout = layout
	cfg.Opts.ListWorkers = common.listWorkers
	cfg.Opts.FetchWorkers = common.fetchWorkers
	cfg.Opts.DeniedThreshold = deniedThreshold
	cfg.Opts.DeleteThreshold = deleteThreshold
	cfg.Opts.EgressBytes = egressBytes
	cfg.Opts.SourceBuckets = splitList(sourceBuckets)
	cfg.Opts.Scope.BasePrefix = common.prefix
	if layout == s3src.S3LayoutPartitioned {
		cfg.Opts.Scope.Accounts = scope.accounts
		cfg.Opts.Scope.Regions = scope.regions
	}

	// S3 files each object under the time it was delivered, which trails
	// the requests in it, so requests from just before midnight on --until
	// can land in the next day's objects. Scan that day too; the filter
	// trims to the window.
	dayAfter := scope.end.AddDate(0, 0, 1)
	cfg.Opts.Scope.Start = scope.start
	cfg.Opts.Scope.End = dayAfter
	f.Operations = splitList(operations)
	f.Buckets = cfg.Opts.SourceBuckets
	f.Since = scope.start
	f.Until = dayAfter
	cfg.Opts.Filter = f

	cfg.Meta = report.Meta{
		Bucket:   cfg.Store.Bucket,
		Accounts: cfg.Opts.Scope.Accounts,
		Regions:  cfg.Opts.Scope.Regions,
		Since:    scope.start,
		Until:    scope.end,
		Narrowed: f.IsNarrowing(),
	}
	return cfg, set, nil
}
