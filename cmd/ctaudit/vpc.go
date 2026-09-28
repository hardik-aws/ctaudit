package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/flowlog"
	"github.com/gsmappdev/ctaudit/internal/report"
	"github.com/gsmappdev/ctaudit/internal/s3src"
	"github.com/gsmappdev/ctaudit/internal/sink"
	"github.com/gsmappdev/ctaudit/internal/stats"
	"github.com/gsmappdev/ctaudit/internal/vpcrules"
)

// vpcActions are the flow log actions, used to validate --action and to
// send every action's metric.
var vpcActions = []string{"ACCEPT", "REJECT"}

// vpcEmitModes are the --emit-flows values.
var vpcEmitModes = []string{"reject", "all", "none"}

// vpcConfig is the parsed vpc command line.
type vpcConfig struct {
	Store    storeConfig
	HTMLPath string
	PDFPath  string
	TopN     int
	FailOn   findings.Severity
	// FailOff is true when --fail-on is "none".
	FailOff bool
	// EmitFlows is which matching flows go to Loki and JSONL: reject, all,
	// or none.
	EmitFlows string
	Opts      engine.VPCOptions
	Meta      report.Meta
	Observe   observeFlags
	Log       logFlags
}

func runVPC(ctx context.Context, args []string, stdout, stderr io.Writer, newStore storeFactory, now time.Time) int {
	cfg, _, err := parseVPCArgsFlags(args, now, stderr, nil)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}

	log := cfg.Log.logger(stderr)
	cfg.Opts.Debug, cfg.Store.Log, cfg.Observe.log = log, log, log
	debugScope(log, "vpc", cfg.Store, cfg.Opts.Scope, cfg.Opts.Filter.Since, cfg.Opts.Filter.Until, cfg.Opts.ListWorkers, cfg.Opts.FetchWorkers)

	// Sinks are built before any S3 call so a bad URL or credential fails
	// fast.
	obs, err := newObserver("vpc", cfg.Observe, now)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}
	defer obs.abort()
	cfg.Opts.Emit = obs.vpcEmit(cfg.EmitFlows)

	store, err := newStore(ctx, cfg.Store)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return exitFailed
	}

	res, err := engine.RunVPC(ctx, store, cfg.Opts)
	if err != nil {
		fmt.Fprintf(stderr, "ctaudit: scan failed: %v\n", err)
		return exitFailed
	}
	cfg.Meta.GeneratedAt = time.Now().UTC()
	debugLog(log, "scan done", "objects", res.ObjectsScanned, "records", res.RecordsRead, "matched", res.MatchedRecords,
		"findings", len(res.Findings), "errors", len(res.Errors), "dur", res.Elapsed)
	warnIfEmpty(stderr, res.ObjectsScanned, cfg.Opts.Scope)

	if err := report.VPCTerminal(stdout, res, cfg.Meta, cfg.TopN); err != nil {
		fmt.Fprintf(stderr, "ctaudit: write summary: %v\n", err)
		return exitFailed
	}
	if cfg.HTMLPath != "" {
		err := writeFile(cfg.HTMLPath, func(w io.Writer) error { return report.VPCHTML(w, res, cfg.Meta, cfg.TopN) })
		if err != nil {
			fmt.Fprintf(stderr, "ctaudit: %v\n", err)
			return exitFailed
		}
		fmt.Fprintf(stdout, "\nHTML report written to %s\n", cfg.HTMLPath)
	}
	if cfg.PDFPath != "" {
		err := writeFile(cfg.PDFPath, func(w io.Writer) error { return report.VPCPDF(w, res, cfg.Meta, cfg.TopN) })
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
	if !obs.finish(ctx, stderr, res.Findings, common, vpcMetrics(res)) {
		return exitFailed
	}
	if len(res.Errors) > 0 {
		return exitFailed
	}
	if sev, ok := vpcrules.MaxSeverity(res.Findings); ok && !cfg.FailOff && sev >= cfg.FailOn {
		return exitFindings
	}
	return exitOK
}

// parseVPCArgsFlags parses the vpc flags and reports which were set on the
// command line. extra, when not nil, registers additional flags first, so
// serve can reuse this for its own flag set.
func parseVPCArgsFlags(args []string, now time.Time, usage io.Writer, extra func(*flag.FlagSet)) (vpcConfig, map[string]bool, error) {
	fs := flag.NewFlagSet("ctaudit vpc", flag.ContinueOnError)
	fs.SetOutput(usage)

	var (
		cfg                                vpcConfig
		common                             commonFlags
		actions, srcCIDRs, dstCIDRs, ports string
		protocols, interfaces, vpcs        string
		failOn, egress                     string
		scanPorts, sweepHosts              int
	)

	common.register(fs, now, "VPC Flow Logs bucket (required)", "key prefix the flow log writes under, before AWSLogs/")
	fs.StringVar(&cfg.Opts.Scope.OrgID, "org-id", "", "AWS Organizations ID segment in the key, e.g. o-abc123, when logs are delivered under an organization")
	fs.StringVar(&actions, "action", "", "comma-separated actions: ACCEPT, REJECT")
	fs.StringVar(&srcCIDRs, "src-cidr", "", "comma-separated CIDRs or addresses; matches srcaddr or pkt-srcaddr")
	fs.StringVar(&dstCIDRs, "dst-cidr", "", "comma-separated CIDRs or addresses; matches dstaddr or pkt-dstaddr")
	fs.StringVar(&ports, "ports", "", "comma-separated ports and ranges, e.g. 22,8000-8100; matches either end")
	fs.StringVar(&protocols, "protocol", "", "comma-separated protocol names (tcp, udp, icmp, icmpv6, gre, esp, ah, sctp) or numbers")
	fs.StringVar(&interfaces, "interfaces", "", "comma-separated network interface IDs (eni-...)")
	fs.StringVar(&vpcs, "vpcs", "", "comma-separated VPC IDs; flows from formats without vpc-id never match")
	fs.IntVar(&scanPorts, "scan-ports", 25, "distinct rejected destination ports that make a public source a port scanner")
	fs.IntVar(&sweepHosts, "sweep-hosts", 50, "distinct private destinations that make a source a host sweep")
	fs.StringVar(&egress, "egress-bytes", "1GiB", "bytes one private host must send to public addresses for a finding; plain bytes or K, M, G, T (binary)")
	fs.StringVar(&cfg.EmitFlows, "emit-flows", "reject", "matching flows sent to --loki and --jsonl: reject, all, or none (findings are always sent)")
	fs.StringVar(&failOn, "fail-on", "high", "exit 1 when a finding is at or above this severity: none, low, medium, high, critical")
	fs.StringVar(&cfg.HTMLPath, "html", "vpc-report.html", `HTML report path; "" to skip`)
	fs.StringVar(&cfg.PDFPath, "pdf", "", "also write a printable PDF report to this .pdf path")
	fs.IntVar(&cfg.Opts.MaxEvents, "max-events", 200, "matching flows kept for the flows table (earliest first)")

	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return vpcConfig{}, nil, err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	scope, err := common.resolve(fs)
	if err != nil {
		return vpcConfig{}, nil, err
	}
	fail := func(err error) (vpcConfig, map[string]bool, error) { return vpcConfig{}, nil, err }

	if cfg.Opts.MaxEvents < 1 {
		return fail(errors.New("--max-events must be at least 1"))
	}
	if scanPorts <= 0 {
		return fail(errors.New("--scan-ports must be greater than 0"))
	}
	if sweepHosts <= 0 {
		return fail(errors.New("--sweep-hosts must be greater than 0"))
	}
	egressBytes, err := parseSize(egress)
	if err != nil {
		return fail(fmt.Errorf("--egress-bytes: %w", err))
	}
	cfg.EmitFlows = strings.ToLower(strings.TrimSpace(cfg.EmitFlows))
	if !slices.Contains(vpcEmitModes, cfg.EmitFlows) {
		return fail(fmt.Errorf("--emit-flows: %q is not one of %s", cfg.EmitFlows, strings.Join(vpcEmitModes, ", ")))
	}
	if err := checkHTMLPath(cfg.HTMLPath); err != nil {
		return fail(err)
	}
	if err := checkPDFPath(cfg.PDFPath); err != nil {
		return fail(err)
	}

	var f flowlog.Filter
	for _, a := range splitList(actions) {
		a = strings.ToUpper(a)
		if !slices.Contains(vpcActions, a) {
			return fail(fmt.Errorf("--action: %q is not one of %s", a, strings.Join(vpcActions, ", ")))
		}
		f.Actions = append(f.Actions, a)
	}
	if f.SrcCIDRs, err = flowlog.ParseCIDRs(splitList(srcCIDRs)); err != nil {
		return fail(fmt.Errorf("--src-cidr: %w", err))
	}
	if f.DstCIDRs, err = flowlog.ParseCIDRs(splitList(dstCIDRs)); err != nil {
		return fail(fmt.Errorf("--dst-cidr: %w", err))
	}
	if f.Ports, err = flowlog.ParsePorts(splitList(ports)); err != nil {
		return fail(fmt.Errorf("--ports: %w", err))
	}
	if f.Protocols, err = flowlog.ParseProtocols(splitList(protocols)); err != nil {
		return fail(fmt.Errorf("--protocol: %w", err))
	}
	f.Interfaces = splitList(interfaces)
	f.VPCs = splitList(vpcs)

	if strings.EqualFold(strings.TrimSpace(failOn), "none") {
		cfg.FailOff = true
	} else {
		sev, err := findings.ParseSeverity(failOn)
		if err != nil {
			return fail(fmt.Errorf("--fail-on: %w", err))
		}
		cfg.FailOn = sev
	}

	cfg.Store = common.store
	cfg.TopN = common.topN
	cfg.Observe = common.obs
	cfg.Log = common.log
	cfg.Opts.ListWorkers = common.listWorkers
	cfg.Opts.FetchWorkers = common.fetchWorkers
	cfg.Opts.Rules = vpcrules.Options{ScanPorts: scanPorts, SweepHosts: sweepHosts, EgressBytes: egressBytes}
	cfg.Opts.Scope.Service = s3src.ServiceVPC
	cfg.Opts.Scope.BasePrefix = common.prefix
	cfg.Opts.Scope.Accounts = scope.accounts
	cfg.Opts.Scope.Regions = scope.regions

	// A flow log object is filed under the day it was delivered, so flows
	// that start just before midnight on --until can land in the next day's
	// prefix. Scan that day too; the filter trims to the window on start.
	dayAfter := scope.end.AddDate(0, 0, 1)
	cfg.Opts.Scope.Start = scope.start
	cfg.Opts.Scope.End = dayAfter
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

// parseSize parses a positive byte count: plain digits, or digits followed
// by K, M, G, or T (binary multiples), with an optional "iB" or "B".
func parseSize(s string) (int64, error) {
	bad := fmt.Errorf("%q is not a positive size such as 1073741824, 500M, or 1GiB", s)
	u := strings.ToUpper(strings.TrimSpace(s))
	if strings.HasSuffix(u, "IB") {
		u = u[:len(u)-2]
	} else if strings.HasSuffix(u, "B") {
		u = u[:len(u)-1]
	}
	mult := int64(1)
	if n := len(u); n > 0 {
		switch u[n-1] {
		case 'K':
			mult = 1 << 10
		case 'M':
			mult = 1 << 20
		case 'G':
			mult = 1 << 30
		case 'T':
			mult = 1 << 40
		}
		if mult > 1 {
			u = u[:n-1]
		}
	}
	v, err := strconv.ParseInt(u, 10, 64)
	if err != nil || v <= 0 || v > math.MaxInt64/mult {
		return 0, bad
	}
	return v * mult, nil
}

// vpcEmit streams matching flows to the sink, or returns nil when no sink is
// set or mode is "none". In "reject" mode, ACCEPT flows are dropped before
// encoding so only REJECT flows (and any flow with an action other than
// ACCEPT) go to Loki and JSONL; statistics and metrics still cover every
// flow.
func (o *observer) vpcEmit(mode string) func() func(flowlog.Entry) {
	if o.sink == nil || mode == "none" {
		return nil
	}
	dropAccepts := mode != "all"
	return func() func(flowlog.Entry) {
		w := o.sink.NewWriter()
		return func(e flowlog.Entry) {
			if dropAccepts && e.Action == "ACCEPT" {
				return
			}
			w.Write(o.enc.VPC(e))
		}
	}
}

// vpcMetrics adds the VPC families. Every action and severity is always
// sent so no stale series survive.
func vpcMetrics(res engine.VPCResult) func(*sink.Metrics) {
	return func(m *sink.Metrics) {
		var flows map[string]int
		var bytes, packets int64
		if sum := res.Summary; sum != nil {
			flows, bytes, packets = sum.ByAction, sum.Bytes, sum.Packets
		}
		for _, a := range vpcActions {
			m.GaugeWith("ctaudit_vpc_flows", "Matching flows in the last run, by action.", "action", a, float64(flows[a]))
		}
		m.Gauge("ctaudit_vpc_bytes", "Bytes in matching flows in the last run.", float64(bytes))
		m.Gauge("ctaudit_vpc_packets", "Packets in matching flows in the last run.", float64(packets))
		counts := map[findings.Severity]int{}
		for _, f := range res.Findings {
			counts[f.Severity]++
		}
		for _, sev := range []findings.Severity{findings.SevLow, findings.SevMedium, findings.SevHigh, findings.SevCritical} {
			m.GaugeWith("ctaudit_vpc_findings", "Findings in the last run, by severity.", "severity",
				strings.ToLower(sev.String()), float64(counts[sev]))
		}
	}
}

// mergeVPC folds the stored VPC ticks into one result, keeping the earliest
// maxEvents flows, and re-runs the rules over the merged summary so /report
// sees thresholds crossed across ticks. Each tick's summary is already
// bounded, and the merge keeps the caps.
func mergeVPC(ticks []tickResult, maxEvents int, rules vpcrules.Options) engine.VPCResult {
	out := engine.VPCResult{Summary: stats.NewVPCSummary(rules.Limits())}
	for _, t := range ticks {
		r := t.VPC
		if r == nil {
			continue
		}
		if r.Summary != nil {
			out.Summary.Merge(r.Summary)
		}
		out.Matches = append(out.Matches, r.Matches...)
		out.ObjectsScanned += r.ObjectsScanned
		out.RecordsRead += r.RecordsRead
		out.MatchedRecords += r.MatchedRecords
		out.Errors = append(out.Errors, r.Errors...)
		out.Elapsed += r.Elapsed
	}
	sort.SliceStable(out.Matches, func(i, j int) bool { return out.Matches[i].Start.Before(out.Matches[j].Start) })
	if len(out.Matches) > maxEvents {
		out.Matches = out.Matches[:maxEvents]
	}
	out.Findings, out.FindingsDropped = vpcrules.Detect(out.Summary, rules)
	return out
}
