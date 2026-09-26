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
	"github.com/gsmappdev/ctaudit/internal/report"
	"github.com/gsmappdev/ctaudit/internal/s3src"
	"github.com/gsmappdev/ctaudit/internal/waflog"
	"github.com/gsmappdev/ctaudit/internal/wafrules"
)

// wafActions are the actions AWS WAF can log, used to validate --action.
var wafActions = []string{"ALLOW", "BLOCK", "COUNT", "CAPTCHA", "CHALLENGE"}

// wafConfig is the parsed waf command line.
type wafConfig struct {
	Store    storeConfig
	HTMLPath string
	PDFPath  string
	TopN     int
	FailOn   findings.Severity
	// FailOff is true when --fail-on is "none".
	FailOff bool
	Opts    engine.WAFOptions
	Meta    report.Meta
	Observe observeFlags
	Log     logFlags
}

func runWAF(ctx context.Context, args []string, stdout, stderr io.Writer, newStore storeFactory, now time.Time) int {
	cfg, err := parseWAFArgsTo(args, now, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}

	log := cfg.Log.logger(stderr)
	cfg.Opts.Debug, cfg.Store.Log, cfg.Observe.log = log, log, log
	debugScope(log, "waf", cfg.Store, cfg.Opts.Scope, cfg.Opts.Filter.Since, cfg.Opts.Filter.Until, cfg.Opts.ListWorkers, cfg.Opts.FetchWorkers)

	// Sinks are built before any S3 call so a bad URL or credential fails
	// fast.
	obs, err := newObserver("waf", cfg.Observe, now)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}
	defer obs.abort()
	cfg.Opts.Emit = obs.wafEmit()

	store, err := newStore(ctx, cfg.Store)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}

	res, err := engine.RunWAF(ctx, store, cfg.Opts)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: scan failed: %v\n", err)
		return exitFailed
	}
	cfg.Meta.GeneratedAt = time.Now().UTC()
	debugLog(log, "scan done", "objects", res.ObjectsScanned, "records", res.RecordsRead, "matched", res.MatchedRecords,
		"findings", len(res.Findings), "web_acls", len(res.WebACLs), "errors", len(res.Errors), "dur", res.Elapsed)
	warnIfEmpty(stderr, res.ObjectsScanned, cfg.Opts.Scope)
	if len(res.WebACLs) == 0 {
		fmt.Fprintln(stderr, "ctaudit: warning: no web ACLs found under WAFLogs/ for the given accounts and regions")
	}

	if err := report.WAFTerminal(stdout, res, cfg.Meta, cfg.TopN); err != nil {
		fmt.Fprintf(stderr, "ctaudit: write summary: %v\n", err)
		return exitFailed
	}
	if cfg.HTMLPath != "" {
		err := writeFile(cfg.HTMLPath, func(w io.Writer) error { return report.WAFHTML(w, res, cfg.Meta, cfg.TopN) })
		if err != nil {
			fmt.Fprintf(stderr, "ctaudit: %v\n", err)
			return exitFailed
		}
		fmt.Fprintf(stdout, "\nHTML report written to %s\n", cfg.HTMLPath)
	}
	if cfg.PDFPath != "" {
		err := writeFile(cfg.PDFPath, func(w io.Writer) error { return report.WAFPDF(w, res, cfg.Meta, cfg.TopN) })
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
	if !obs.finish(ctx, stderr, res.Findings, common, wafMetrics(res)) {
		return exitFailed
	}

	// As for CloudTrail and ELB, a partial scan must not look like a clean
	// one.
	if len(res.Errors) > 0 {
		return exitFailed
	}
	if sev, ok := wafrules.MaxSeverity(res.Findings); ok && !cfg.FailOff && sev >= cfg.FailOn {
		return exitFindings
	}
	return exitOK
}

// parseWAFArgs parses the waf flags, discarding usage output.
func parseWAFArgs(args []string, now time.Time) (wafConfig, error) {
	return parseWAFArgsTo(args, now, io.Discard)
}

func parseWAFArgsTo(args []string, now time.Time, usage io.Writer) (wafConfig, error) {
	cfg, _, err := parseWAFArgsFlags(args, now, usage, nil)
	return cfg, err
}

// parseWAFArgsFlags parses the flags and also reports which flags were set on
// the command line. extra, when not nil, registers additional flags first, so
// serve can reuse this for its own flag set.
func parseWAFArgsFlags(args []string, now time.Time, usage io.Writer, extra func(*flag.FlagSet)) (wafConfig, map[string]bool, error) {
	fs := flag.NewFlagSet("ctaudit waf", flag.ContinueOnError)
	fs.SetOutput(usage)

	var (
		cfg            wafConfig
		common         commonFlags
		webACLs        string
		actions        string
		countries      string
		failOn         string
		blockThreshold int
		f              waflog.Filter
	)

	common.register(fs, now, "WAF log bucket (required)", "key prefix WAF writes under, before AWSLogs/")
	fs.StringVar(&cfg.Opts.Scope.OrgID, "org-id", "", "AWS Organizations ID segment in the key, e.g. o-abc123, when logs are delivered under an organization")
	fs.StringVar(&webACLs, "web-acls", "", "comma-separated web ACL names; a log is scanned if its name contains any of them")
	fs.StringVar(&actions, "action", "", "comma-separated actions: ALLOW, BLOCK, COUNT, CAPTCHA, CHALLENGE")
	fs.StringVar(&f.ClientIP, "client-ip", "", "only requests whose client IP contains this text")
	fs.StringVar(&countries, "country", "", "comma-separated two-letter country codes")
	fs.StringVar(&f.Rule, "rule", "", "only requests whose terminating rule contains this text (case-insensitive)")
	fs.StringVar(&f.URI, "uri", "", "only requests whose URI contains this text (case-insensitive)")
	fs.StringVar(&f.Host, "host", "", "only requests whose Host header contains this text (case-insensitive)")
	fs.IntVar(&blockThreshold, "block-threshold", 100, "block count at which a client IP becomes a finding")
	fs.StringVar(&failOn, "fail-on", "critical", "exit 1 when a finding is at or above this severity: none, low, medium, high, critical")
	fs.StringVar(&cfg.HTMLPath, "html", "waf-report.html", `HTML report path; "" to skip`)
	fs.StringVar(&cfg.PDFPath, "pdf", "", "also write a printable PDF report to this .pdf path")
	fs.IntVar(&cfg.Opts.MaxEvents, "max-events", 200, "matching requests kept for the requests table (earliest first)")

	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return wafConfig{}, nil, err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	scope, err := common.resolve(fs)
	if err != nil {
		return wafConfig{}, nil, err
	}
	if cfg.Opts.MaxEvents < 1 {
		return wafConfig{}, nil, errors.New("--max-events must be at least 1")
	}
	if blockThreshold <= 0 {
		return wafConfig{}, nil, errors.New("--block-threshold must be greater than 0")
	}
	if err := checkHTMLPath(cfg.HTMLPath); err != nil {
		return wafConfig{}, nil, err
	}
	if err := checkPDFPath(cfg.PDFPath); err != nil {
		return wafConfig{}, nil, err
	}
	for _, a := range splitList(actions) {
		valid := false
		for _, want := range wafActions {
			if strings.EqualFold(a, want) {
				valid = true
				break
			}
		}
		if !valid {
			return wafConfig{}, nil, fmt.Errorf("--action: %q is not one of %s", a, strings.Join(wafActions, ", "))
		}
		f.Actions = append(f.Actions, strings.ToUpper(a))
	}
	if strings.EqualFold(strings.TrimSpace(failOn), "none") {
		cfg.FailOff = true
	} else {
		sev, err := findings.ParseSeverity(failOn)
		if err != nil {
			return wafConfig{}, nil, fmt.Errorf("--fail-on: %w", err)
		}
		cfg.FailOn = sev
	}

	cfg.Store = common.store
	cfg.TopN = common.topN
	cfg.Observe = common.obs
	cfg.Log = common.log
	cfg.Opts.ListWorkers = common.listWorkers
	cfg.Opts.FetchWorkers = common.fetchWorkers
	cfg.Opts.BlockThreshold = blockThreshold
	cfg.Opts.WebACLs = splitList(webACLs)
	cfg.Opts.Scope.Service = s3src.ServiceWAF
	cfg.Opts.Scope.BasePrefix = common.prefix
	cfg.Opts.Scope.Accounts = scope.accounts
	cfg.Opts.Scope.Regions = scope.regions

	// WAF files each object under the day and hour it was delivered, so
	// requests from just before midnight on --until can land in the next
	// day's prefix. Scan that day too; the filter trims to the window.
	dayAfter := scope.end.AddDate(0, 0, 1)
	cfg.Opts.Scope.Start = scope.start
	cfg.Opts.Scope.End = dayAfter
	f.Countries = splitList(countries)
	f.Since = scope.start
	f.Until = dayAfter
	cfg.Opts.Filter = f

	cfg.Meta = report.Meta{
		Bucket:   cfg.Store.Bucket,
		Accounts: scope.accounts,
		Regions:  scope.regions,
		Since:    scope.start,
		Until:    scope.end,
		Narrowed: f.IsNarrowing() || len(cfg.Opts.WebACLs) > 0,
	}
	return cfg, set, nil
}
