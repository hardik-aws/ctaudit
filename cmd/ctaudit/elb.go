package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/report"
	"github.com/gsmappdev/ctaudit/internal/s3src"
)

// elbConfig is the parsed elb command line.
type elbConfig struct {
	Store    storeConfig
	HTMLPath string
	PDFPath  string
	TopN     int
	Opts     engine.ELBOptions
	Meta     report.Meta
	Observe  observeFlags
	Log      logFlags
}

func runELB(ctx context.Context, args []string, stdout, stderr io.Writer, newStore storeFactory, now time.Time) int {
	cfg, err := parseELBArgsTo(args, now, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}

	log := cfg.Log.logger(stderr)
	cfg.Opts.Debug, cfg.Store.Log, cfg.Observe.log = log, log, log
	debugScope(log, "elb", cfg.Store, cfg.Opts.Scope, cfg.Opts.Filter.Since, cfg.Opts.Filter.Until, cfg.Opts.ListWorkers, cfg.Opts.FetchWorkers)

	// Sinks are built before any S3 call so a bad URL or credential fails
	// fast.
	obs, err := newObserver("elb", cfg.Observe, now)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}
	defer obs.abort()
	cfg.Opts.Emit = obs.elbEmit()

	store, err := newStore(ctx, cfg.Store)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}

	res, err := engine.RunELB(ctx, store, cfg.Opts)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: scan failed: %v\n", err)
		return exitFailed
	}
	cfg.Meta.GeneratedAt = time.Now().UTC()
	debugLog(log, "scan done", "objects", res.ObjectsScanned, "records", res.RecordsRead, "matched", res.MatchedRecords,
		"conns", res.ConnsRead, "matched_conns", res.MatchedConns, "errors", len(res.Errors), "dur", res.Elapsed)
	warnIfEmpty(stderr, res.ObjectsScanned, cfg.Opts.Scope)

	if err := report.ELBTerminal(stdout, res, cfg.Meta, cfg.TopN); err != nil {
		fmt.Fprintf(stderr, "ctaudit: write summary: %v\n", err)
		return exitFailed
	}
	if cfg.HTMLPath != "" {
		err := writeFile(cfg.HTMLPath, func(w io.Writer) error { return report.ELBHTML(w, res, cfg.Meta, cfg.TopN) })
		if err != nil {
			fmt.Fprintf(stderr, "ctaudit: %v\n", err)
			return exitFailed
		}
		fmt.Fprintf(stdout, "\nHTML report written to %s\n", cfg.HTMLPath)
	}
	if cfg.PDFPath != "" {
		err := writeFile(cfg.PDFPath, func(w io.Writer) error { return report.ELBPDF(w, res, cfg.Meta, cfg.TopN) })
		if err != nil {
			fmt.Fprintf(stderr, "ctaudit: %v\n", err)
			return exitFailed
		}
		fmt.Fprintf(stdout, "PDF report written to %s\n", cfg.PDFPath)
	}
	// A failed push fails the run, like an unreadable object.
	// Connection records count toward the common totals.
	common := commonMetrics{
		objects: res.ObjectsScanned,
		read:    res.RecordsRead + res.ConnsRead,
		matched: res.MatchedRecords + res.MatchedConns,
		errors:  len(res.Errors),
		elapsed: res.Elapsed,
	}
	if !obs.finish(ctx, stderr, nil, common, elbMetrics(res)) {
		return exitFailed
	}

	// As for CloudTrail, a partial scan must not look like a clean one.
	if len(res.Errors) > 0 {
		return exitFailed
	}
	return exitOK
}

// parseELBArgs parses the elb flags, discarding usage output.
func parseELBArgs(args []string, now time.Time) (elbConfig, error) {
	return parseELBArgsTo(args, now, io.Discard)
}

func parseELBArgsTo(args []string, now time.Time, usage io.Writer) (elbConfig, error) {
	cfg, _, err := parseELBArgsFlags(args, now, usage, nil)
	return cfg, err
}

// parseELBArgsFlags parses the flags and also reports which flags were set on the
// command line. extra, when not nil, registers additional flags first.
func parseELBArgsFlags(args []string, now time.Time, usage io.Writer, extra func(*flag.FlagSet)) (elbConfig, map[string]bool, error) {
	fs := flag.NewFlagSet("ctaudit elb", flag.ContinueOnError)
	fs.SetOutput(usage)

	var (
		cfg                        elbConfig
		common                     commonFlags
		lbs, kinds, methods, codes string
		f                          elblog.Filter
	)

	common.register(fs, now, "load balancer access log bucket (required)", "key prefix the load balancer writes under, before AWSLogs/")
	fs.StringVar(&lbs, "lb", "", "comma-separated load balancer names; a log is scanned if its name contains any of them")
	fs.StringVar(&kinds, "type", "", "comma-separated load balancer types: alb, nlb, classic (default all)")
	fs.StringVar(&f.ClientIP, "client-ip", "", "only requests whose client IP contains this text")
	fs.StringVar(&f.Host, "host", "", "only requests whose host or SNI domain contains this text (case-insensitive)")
	fs.StringVar(&f.Path, "path", "", "only requests whose URL path contains this text (case-insensitive)")
	fs.StringVar(&methods, "method", "", "comma-separated HTTP methods, e.g. POST,DELETE")
	fs.StringVar(&codes, "status", "", "comma-separated ELB status codes or classes, e.g. 502,4xx")
	fs.StringVar(&f.Target, "target", "", "only requests whose target ip:port contains this text")
	fs.StringVar(&f.UserAgent, "user-agent", "", "only requests whose user agent contains this text (case-insensitive)")
	fs.DurationVar(&f.SlowerThan, "slower-than", 0, "only requests whose total latency is at least this, e.g. 500ms or 2s")
	fs.StringVar(&cfg.HTMLPath, "html", "elb-report.html", `HTML report path; "" to skip`)
	fs.StringVar(&cfg.PDFPath, "pdf", "", "also write a printable PDF report to this .pdf path")
	fs.IntVar(&cfg.Opts.MaxEvents, "max-events", 200, "matching requests kept for the requests table (earliest first)")

	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return elbConfig{}, nil, err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	scope, err := common.resolve(fs)
	if err != nil {
		return elbConfig{}, nil, err
	}
	if cfg.Opts.MaxEvents < 1 {
		return elbConfig{}, nil, errors.New("--max-events must be at least 1")
	}
	if f.SlowerThan < 0 {
		return elbConfig{}, nil, errors.New("--slower-than must not be negative")
	}
	if err := checkHTMLPath(cfg.HTMLPath); err != nil {
		return elbConfig{}, nil, err
	}
	if err := checkPDFPath(cfg.PDFPath); err != nil {
		return elbConfig{}, nil, err
	}
	for _, k := range splitList(kinds) {
		kind, err := elblog.ParseKind(k)
		if err != nil {
			return elbConfig{}, nil, fmt.Errorf("--type: %w", err)
		}
		cfg.Opts.Kinds = append(cfg.Opts.Kinds, kind)
	}

	cfg.Store = common.store
	cfg.TopN = common.topN
	cfg.Observe = common.obs
	cfg.Log = common.log
	cfg.Opts.ListWorkers = common.listWorkers
	cfg.Opts.FetchWorkers = common.fetchWorkers
	cfg.Opts.LBs = splitList(lbs)
	cfg.Opts.Scope.Service = s3src.ServiceELB
	cfg.Opts.Scope.BasePrefix = common.prefix
	cfg.Opts.Scope.Accounts = scope.accounts
	cfg.Opts.Scope.Regions = scope.regions

	// Load balancers file each object under the day its five-minute interval
	// ended, so requests from just before midnight on --until can land in the
	// next day's prefix. Scan that day too; the filter trims to the window.
	dayAfter := scope.end.AddDate(0, 0, 1)
	cfg.Opts.Scope.Start = scope.start
	cfg.Opts.Scope.End = dayAfter
	f.Methods = splitList(methods)
	f.Statuses = splitList(codes)
	f.Since = scope.start
	f.Until = dayAfter
	cfg.Opts.Filter = f

	cfg.Meta = report.Meta{
		Bucket:   cfg.Store.Bucket,
		Accounts: scope.accounts,
		Regions:  scope.regions,
		Since:    scope.start,
		Until:    scope.end,
		Narrowed: f.IsNarrowing() || len(cfg.Opts.LBs) > 0 || len(cfg.Opts.Kinds) > 0,
	}
	return cfg, set, nil
}
