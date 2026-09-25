package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/report"
	"github.com/gsmappdev/ctaudit/internal/s3src"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

const (
	minInterval     = time.Minute
	maxLookback     = 720 * time.Hour
	shutdownGrace   = 10 * time.Second
	reportCSP       = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"
	serveUsage      = "usage: ctaudit serve cloudtrail|elb [flags]"
	day             = 24 * time.Hour
	metricsMIMEType = "text/plain; version=0.0.4; charset=utf-8"
)

// serveRejected are subcommand flags that make no sense for a long-running
// server. They are rejected only when set explicitly.
var serveRejected = []string{"since", "until", "html", "pdf", "pushgateway", "jsonl", "fail-on"}

// serveConfig is the parsed serve command line. Exactly one of ct and elb is
// set; their scope days and filter window are replaced on every tick.
type serveConfig struct {
	sub      string
	interval time.Duration
	lookback time.Duration
	listen   string
	store    storeConfig
	topN     int
	observe  observeFlags
	log      logFlags
	meta     report.Meta
	ct       *config
	elb      *elbConfig
}

func parseServeArgs(args []string, now time.Time, usage io.Writer) (serveConfig, error) {
	if len(args) == 0 {
		return serveConfig{}, errors.New(serveUsage)
	}
	sc := serveConfig{}
	extra := func(fs *flag.FlagSet) {
		fs.DurationVar(&sc.interval, "interval", 15*time.Minute, "time between the start of one scan and the next (minimum 1m)")
		fs.DurationVar(&sc.lookback, "lookback", 24*time.Hour, "size of the rolling scan window (at least --interval, at most 720h)")
		fs.StringVar(&sc.listen, "listen", ":8080", "HTTP listen address for /metrics, /healthz, and /report")
	}

	var set map[string]bool
	switch args[0] {
	case "cloudtrail":
		cfg, s, err := parseArgsFlags(args[1:], now, usage, extra)
		if err != nil {
			return serveConfig{}, err
		}
		sc.sub, sc.ct, set = "cloudtrail", &cfg, s
		sc.store, sc.topN, sc.observe, sc.meta, sc.log = cfg.Store, cfg.TopN, cfg.Observe, cfg.Meta, cfg.Log
	case "elb", "alb":
		cfg, s, err := parseELBArgsFlags(args[1:], now, usage, extra)
		if err != nil {
			return serveConfig{}, err
		}
		sc.sub, sc.elb, set = "elb", &cfg, s
		sc.store, sc.topN, sc.observe, sc.meta, sc.log = cfg.Store, cfg.TopN, cfg.Observe, cfg.Meta, cfg.Log
	default:
		return serveConfig{}, fmt.Errorf("unknown serve subcommand %q; %s", args[0], serveUsage)
	}

	for _, name := range serveRejected {
		if set[name] {
			return serveConfig{}, fmt.Errorf("--%s is not supported by serve", name)
		}
	}
	if sc.interval < minInterval {
		return serveConfig{}, fmt.Errorf("--interval must be at least %v", minInterval)
	}
	if sc.lookback < sc.interval {
		return serveConfig{}, errors.New("--lookback must be at least --interval")
	}
	if sc.lookback > maxLookback {
		return serveConfig{}, fmt.Errorf("--lookback must be at most %v", maxLookback)
	}
	return sc, nil
}

// runServe scans the rolling window every --interval and serves the running
// totals at /metrics until SIGTERM or SIGINT.
func runServe(ctx context.Context, args []string, stdout, stderr io.Writer, newStore storeFactory, now func() time.Time) int {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := parseServeArgs(args, now(), stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}

	log := cfg.log.logger(stderr)
	cfg.setLogger(log)

	// Build one observer to validate the Loki settings before any S3 call or
	// bind; each tick builds its own.
	obs, err := newObserver(cfg.sub, cfg.tickObserve(), now())
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}
	obs.abort()

	store, err := newStore(ctx, cfg.store)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}
	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: listen: %v\n", err)
		return exitFailed
	}

	s := newServer(cfg, store, now, stderr)
	srv := &http.Server{Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	fmt.Fprintf(stdout, "ctaudit serve: %s listening on %s, interval %v, lookback %v\n", cfg.sub, ln.Addr(), cfg.interval, cfg.lookback)

	loopCtx, cancelLoop := context.WithCancel(ctx)
	defer cancelLoop()
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	loopDone := make(chan struct{})
	go func() {
		s.loop(loopCtx, ticker.C)
		close(loopDone)
	}()

	code := exitOK
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		fmt.Fprintf(stderr, "ctaudit: http: %v\n", err)
		code = exitFailed
	}
	cancelLoop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(stderr, "ctaudit: http shutdown: %v\n", err)
	}
	<-loopDone
	return code
}

// tickObserve keeps only the observer settings serve supports: Loki and the
// job label.
//
// Serve stamps Loki lines with their record time unless --loki-time says
// otherwise, so dashboards chart request and event times.
func (c serveConfig) tickObserve() observeFlags {
	lokiTime := c.observe.lokiTime
	if lokiTime == "" {
		lokiTime = "event"
	}
	return observeFlags{loki: c.observe.loki, lokiTenant: c.observe.lokiTenant, lokiTime: lokiTime,
		pushJob: c.observe.pushJob, log: c.observe.log}
}

// setLogger hands the debug logger, which may be nil, to the store, the
// observers, and the engine.
func (c *serveConfig) setLogger(log *slog.Logger) {
	c.store.Log, c.observe.log = log, log
	if c.ct != nil {
		c.ct.Opts.Debug = log
	}
	if c.elb != nil {
		c.elb.Opts.Debug = log
	}
}

// server runs the scan loop and answers HTTP requests from the shared state.
type server struct {
	cfg    serveConfig
	state  *serveState
	store  s3src.ObjectStore
	now    func() time.Time
	stderr io.Writer
	log    *slog.Logger
}

func newServer(cfg serveConfig, store s3src.ObjectStore, now func() time.Time, stderr io.Writer) *server {
	return &server{
		cfg:    cfg,
		state:  newServeState(cfg.sub, cfg.interval, cfg.lookback),
		store:  store,
		now:    now,
		stderr: stderr,
		log:    cfg.observe.log,
	}
}

// loop runs one tick now and one more on every trigger until ctx is done.
// Ticks run on this goroutine, so they never overlap; a time.Ticker drops
// the ticks a slow scan misses, so the next one starts as soon as it ends.
func (s *server) loop(ctx context.Context, trigger <-chan time.Time) {
	s.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-trigger:
			if ctx.Err() != nil {
				return
			}
			s.tick(ctx)
		}
	}
}

// window returns the tick's exact window and the scope days that cover it:
// the UTC days from since to until, plus one day because objects are filed
// under their delivery day.
func (s *server) window(until time.Time) (since, scopeStart, scopeEnd time.Time) {
	since = until.Add(-s.cfg.lookback)
	return since, since.Truncate(day), until.Truncate(day).Add(day)
}

// tick scans the window once, skipping keys already read, and commits the
// result only if every Loki line was delivered.
func (s *server) tick(ctx context.Context) {
	started := s.now()
	until := started.UTC()
	since, scopeStart, scopeEnd := s.window(until)
	debugLog(s.log, "tick start", "subcommand", s.cfg.sub, "since", since, "until", until,
		"scope_start", scopeStart.Format(dayLayout), "scope_end", scopeEnd.Format(dayLayout), "seen_keys", s.state.seenCount())

	var (
		t       tickResult
		keys    []string
		fs      []findings.Finding
		objects int
		read    int
		matched int
		errs    int
	)
	obs, err := newObserver(s.cfg.sub, s.cfg.tickObserve(), until)
	if err == nil {
		switch {
		case s.cfg.ct != nil:
			opts := s.cfg.ct.Opts
			opts.Scope.Start, opts.Scope.End = scopeStart, scopeEnd
			opts.Filter.Since, opts.Filter.Until = since, until
			opts.Skip = s.state.isSeen
			opts.Emit = obs.eventEmit()
			var res engine.Result
			if res, err = engine.Run(ctx, s.store, opts); err == nil {
				t.CT = &res
				keys, fs, errs = res.ReadKeys, res.Findings, len(res.Errors)
				objects, read, matched = res.ObjectsScanned, res.RecordsRead, res.MatchedRecords
			}
		default:
			opts := s.cfg.elb.Opts
			opts.Scope.Start, opts.Scope.End = scopeStart, scopeEnd
			opts.Filter.Since, opts.Filter.Until = since, until
			opts.Skip = s.state.isSeen
			opts.Emit = obs.elbEmit()
			var res engine.ELBResult
			if res, err = engine.RunELB(ctx, s.store, opts); err == nil {
				t.ELB = &res
				keys, errs = res.ReadKeys, len(res.Errors)
				objects, read, matched = res.ObjectsScanned, res.RecordsRead+res.ConnsRead, res.MatchedRecords+res.MatchedConns
			}
		}
		if err != nil {
			obs.abort()
		}
	}

	result := "failed"
	reason := "scan error"
	if err == nil {
		reason = "loki push failed"
		// finish prints its own error; a failed Loki push commits nothing so
		// the next tick reads the same objects again.
		if obs.finish(ctx, s.stderr, fs, commonMetrics{}, nil) {
			result, reason = "ok", "all objects read, sink delivered"
			if errs > 0 {
				result, reason = "partial", "some objects unreadable; they stay unseen and are retried"
			}
		}
	}
	dur := s.now().Sub(started)
	if result == "failed" {
		s.state.fail(until, dur)
	} else {
		s.state.commit(until, t, keys, errs, dur)
	}
	prunedKeys, prunedTicks := s.state.prune(until)
	debugLog(s.log, "tick end", "result", result, "reason", reason, "committed_keys", len(keys),
		"pruned_keys", prunedKeys, "pruned_ticks", prunedTicks, "seen_keys", s.state.seenCount())

	line := fmt.Sprintf("ctaudit serve: %s tick %s objects=%d records=%d matched=%d errors=%d dur=%v",
		s.cfg.sub, result, objects, read, matched, errs, dur.Round(time.Millisecond))
	if err != nil {
		line += fmt.Sprintf(" err=%q", err.Error())
	}
	fmt.Fprintln(s.stderr, line)
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", metricsMIMEType)
		io.WriteString(w, s.state.metrics().Text())
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /report", s.serveReport)
	if s.log == nil {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		mux.ServeHTTP(rec, r)
		s.log.Debug("http request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "bytes", rec.bytes, "dur", time.Since(started))
	})
}

// statusRecorder remembers the status and size of a response for the debug
// log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// serveReport renders the HTML report for the whole window by merging every
// committed tick.
func (s *server) serveReport(w http.ResponseWriter, _ *http.Request) {
	ticks := s.state.snapshot()
	if len(ticks) == 0 {
		http.Error(w, "no scan has completed yet", http.StatusServiceUnavailable)
		return
	}
	now := s.now().UTC()
	since, _, _ := s.window(now)
	meta := s.cfg.meta
	meta.Since, meta.Until = since.Truncate(day), now.Truncate(day)
	meta.GeneratedAt = now

	var buf bytes.Buffer
	var err error
	if s.cfg.ct != nil {
		err = report.HTML(&buf, mergeCT(ticks, s.cfg.ct.Opts.MaxEvents), meta, s.cfg.topN)
	} else {
		err = report.ELBHTML(&buf, mergeELB(ticks, s.cfg.elb.Opts.MaxEvents), meta, s.cfg.topN)
	}
	if err != nil {
		fmt.Fprintf(s.stderr, "ctaudit serve: report: %v\n", err)
		http.Error(w, "report failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", reportCSP)
	w.Write(buf.Bytes())
}

// mergeCT folds the stored CloudTrail ticks into one result. The findings of
// every tick are kept; the match list keeps the earliest maxEvents.
func mergeCT(ticks []tickResult, maxEvents int) engine.Result {
	out := engine.Result{Summary: stats.NewSummary(), SeverityCounts: map[findings.Severity]int{}}
	for _, t := range ticks {
		r := t.CT
		if r == nil {
			continue
		}
		out.Summary.Merge(r.Summary)
		out.Findings = append(out.Findings, r.Findings...)
		out.Matches = append(out.Matches, r.Matches...)
		out.ObjectsScanned += r.ObjectsScanned
		out.RecordsRead += r.RecordsRead
		out.MatchedRecords += r.MatchedRecords
		out.DroppedFindings += r.DroppedFindings
		out.Errors = append(out.Errors, r.Errors...)
		out.Elapsed += r.Elapsed
		for sev, n := range r.SeverityCounts {
			out.SeverityCounts[sev] += n
		}
		if r.HasFindings && (!out.HasFindings || r.MaxSeverity > out.MaxSeverity) {
			out.MaxSeverity = r.MaxSeverity
		}
		out.HasFindings = out.HasFindings || r.HasFindings
	}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.Time.Before(b.Time)
	})
	sort.SliceStable(out.Matches, func(i, j int) bool { return out.Matches[i].EventTime.Before(out.Matches[j].EventTime) })
	if len(out.Matches) > maxEvents {
		out.Matches = out.Matches[:maxEvents]
	}
	return out
}

// mergeELB folds the stored ELB ticks into one result, keeping the earliest
// maxEvents requests and connections.
func mergeELB(ticks []tickResult, maxEvents int) engine.ELBResult {
	out := engine.ELBResult{Summary: stats.NewELBSummary(), Conns: stats.NewConnSummary()}
	for _, t := range ticks {
		r := t.ELB
		if r == nil {
			continue
		}
		out.Summary.Merge(r.Summary)
		out.Conns.Merge(r.Conns)
		out.Matches = append(out.Matches, r.Matches...)
		out.ConnMatches = append(out.ConnMatches, r.ConnMatches...)
		out.ObjectsScanned += r.ObjectsScanned
		out.RecordsRead += r.RecordsRead
		out.MatchedRecords += r.MatchedRecords
		out.ConnsRead += r.ConnsRead
		out.MatchedConns += r.MatchedConns
		out.Errors = append(out.Errors, r.Errors...)
		out.Elapsed += r.Elapsed
	}
	for _, list := range []*[]elblog.Entry{&out.Matches, &out.ConnMatches} {
		l := *list
		sort.SliceStable(l, func(i, j int) bool { return l[i].Time.Before(l[j].Time) })
		if len(l) > maxEvents {
			*list = l[:maxEvents]
		}
	}
	return out
}
