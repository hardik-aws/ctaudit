package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/sink"
)

// observeFlags send a run's matches to Loki or a JSON Lines file and its
// metrics to a Prometheus Pushgateway. Credentials come only from the
// environment (see sink.AuthFromEnv), never from flags.
type observeFlags struct {
	pushgateway string
	pushJob     string
	loki        string
	lokiTenant  string
	// lokiTime is "scan" or "event"; "" takes the command's default.
	lokiTime string
	jsonl    string
	// log is not a flag: the caller sets it from --debug.
	log *slog.Logger
}

func (o *observeFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&o.pushgateway, "pushgateway", "", "Prometheus Pushgateway URL to push run metrics to")
	fs.StringVar(&o.pushJob, "push-job", "ctaudit", "job label for pushed metrics and Loki lines")
	fs.StringVar(&o.loki, "loki", "", "Loki base URL to stream every matching record to")
	fs.StringVar(&o.lokiTenant, "loki-tenant", "", "Loki tenant, sent as the X-Scope-OrgID header")
	fs.StringVar(&o.lokiTime, "loki-time", "", "Loki line timestamp: scan (when shipped) or event (record time); default scan, and event under serve")
	fs.StringVar(&o.jsonl, "jsonl", "", "also write every matching record to this JSON Lines file")
}

// getenv is os.Getenv; tests set variables with t.Setenv instead.
var getenv = os.Getenv

// observer holds the sinks for one run. A nil sink or pushgateway means that
// output is off.
type observer struct {
	sink   sink.Sink
	loki   *sink.Loki
	push   *sink.Pushgateway
	enc    sink.Encoder
	closed bool
	log    *slog.Logger
}

// newObserver validates the flags and environment and builds the sinks. It
// runs before any S3 call, so a bad setting fails fast. The JSONL file is
// created last so no earlier error can leave it behind.
func newObserver(sub string, o observeFlags, now time.Time) (*observer, error) {
	obs := &observer{enc: sink.Encoder{Job: o.pushJob, Subcommand: sub, RunID: runID(now)}, log: o.log}

	lokiAuth, err := sink.AuthFromEnv("CTAUDIT_LOKI", getenv)
	if err != nil {
		return nil, err
	}
	pushAuth, err := sink.AuthFromEnv("CTAUDIT_PUSHGATEWAY", getenv)
	if err != nil {
		return nil, err
	}
	if o.pushgateway != "" {
		obs.push = &sink.Pushgateway{URL: o.pushgateway, Job: o.pushJob, Subcommand: sub, Auth: pushAuth, Log: o.log}
		if err := obs.push.Check(); err != nil {
			return nil, err
		}
	}
	eventTime := false
	switch o.lokiTime {
	case "", "scan":
	case "event":
		eventTime = true
	default:
		return nil, fmt.Errorf("--loki-time must be scan or event, not %q", o.lokiTime)
	}
	var sinks []sink.Sink
	if o.loki != "" {
		l, err := sink.NewLoki(sink.LokiConfig{URL: o.loki, Tenant: o.lokiTenant, Auth: lokiAuth, Log: o.log, EventTime: eventTime})
		if err != nil {
			return nil, err
		}
		obs.loki = l
		sinks = append(sinks, l)
	}
	if o.jsonl != "" {
		j, err := sink.NewJSONL(o.jsonl)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, j)
	}
	switch len(sinks) {
	case 0:
	case 1:
		obs.sink = sinks[0]
	default:
		obs.sink = sink.Multi(sinks...)
	}
	return obs, nil
}

// runID is the scan time plus a random suffix, so two runs started in the
// same second still differ.
func runID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

// eventEmit streams CloudTrail matches, or returns nil when no sink is set.
func (o *observer) eventEmit() func() func(ctevent.Record) {
	if o.sink == nil {
		return nil
	}
	return func() func(ctevent.Record) {
		w := o.sink.NewWriter()
		return func(r ctevent.Record) { w.Write(o.enc.Event(r)) }
	}
}

// elbEmit streams ELB matches, or returns nil when no sink is set.
func (o *observer) elbEmit() func() func(elblog.Entry) {
	if o.sink == nil {
		return nil
	}
	return func() func(elblog.Entry) {
		w := o.sink.NewWriter()
		return func(e elblog.Entry) { w.Write(o.enc.ELB(e)) }
	}
}

// abort closes the sink if finish never ran, for example after a failed scan
// or report. Its error is dropped because the run has already failed. It is
// safe to defer.
func (o *observer) abort() {
	if o.sink != nil && !o.closed {
		o.closed = true
		_ = o.sink.Close()
	}
}

// finish writes the findings, closes the sink, and pushes the metrics built
// by fill. It reports whether every output succeeded; failures are printed.
func (o *observer) finish(ctx context.Context, stderr io.Writer, fs []findings.Finding, common commonMetrics, fill func(*sink.Metrics)) bool {
	ok := true
	if o.sink != nil && !o.closed {
		o.closed = true
		if len(fs) > 0 {
			w := o.sink.NewWriter()
			for _, f := range fs {
				w.Write(o.enc.Finding(f))
			}
		}
		err := o.sink.Close()
		debugLog(o.log, "sink closed", "findings", len(fs), "err", err)
		if err != nil {
			fmt.Fprintf(stderr, "ctaudit: %v\n", err)
			ok = false
		}
		if n := o.lokiRejected(); n > 0 {
			fmt.Fprintf(stderr, "ctaudit: warning: loki refused entries in %d pushes as too old or too far behind their stream; "+
				"the rest of each push was stored\n", n)
		}
	}
	if o.push == nil {
		return ok
	}
	m := sink.NewMetrics()
	common.add(m, ok)
	fill(m)
	if err := o.push.Push(ctx, m); err != nil {
		fmt.Fprintf(stderr, "ctaudit: %v\n", err)
		return false
	}
	return ok
}

// lokiRejected returns the pushes Loki refused in part for entry age.
func (o *observer) lokiRejected() int64 {
	if o.loki == nil {
		return 0
	}
	return o.loki.Rejected()
}

// commonMetrics are the counters every subcommand pushes.
type commonMetrics struct {
	objects, read, matched, errors int
	elapsed                        time.Duration
}

func (c commonMetrics) add(m *sink.Metrics, sinkOK bool) {
	now := float64(time.Now().UnixNano()) / 1e9
	m.Gauge("ctaudit_objects_scanned", "Log objects read in the last run.", float64(c.objects))
	m.Gauge("ctaudit_records_read", "Records decoded in the last run.", float64(c.read))
	m.Gauge("ctaudit_records_matched", "Records that passed the filters in the last run.", float64(c.matched))
	m.Gauge("ctaudit_scan_errors", "Objects that could not be read in the last run.", float64(c.errors))
	m.Gauge("ctaudit_scan_duration_seconds", "Wall time of the last scan.", c.elapsed.Seconds())
	m.Gauge("ctaudit_last_run_timestamp_seconds", "Unix time the last run finished.", now)
	if c.errors == 0 && sinkOK {
		m.Gauge("ctaudit_last_success_timestamp_seconds", "Unix time of the last complete run.", now)
	}
}

// cloudTrailMetrics adds the CloudTrail families. Every severity is always
// sent so no stale series survive.
func cloudTrailMetrics(res engine.Result) func(*sink.Metrics) {
	return func(m *sink.Metrics) {
		counts := map[findings.Severity]int{}
		for _, f := range res.Findings {
			counts[f.Severity]++
		}
		for _, sev := range []findings.Severity{findings.SevLow, findings.SevMedium, findings.SevHigh, findings.SevCritical} {
			m.GaugeWith("ctaudit_findings", "Findings in the last run, by severity.", "severity",
				strings.ToLower(sev.String()), float64(counts[sev]))
		}
		m.Gauge("ctaudit_findings_dropped", "Findings discarded past the findings cap.", float64(res.DroppedFindings))
		m.Gauge("ctaudit_cloudtrail_write_events", "Matching mutating events.", float64(res.Summary.WriteEvents))
		m.Gauge("ctaudit_cloudtrail_error_events", "Matching events that returned an error code.", float64(res.Summary.ErrorEvents))
	}
}

// elbMetrics adds the ELB families. Every status class is always sent.
func elbMetrics(res engine.ELBResult) func(*sink.Metrics) {
	return func(m *sink.Metrics) {
		classes := map[string]int{}
		for status, n := range res.Summary.ByStatus {
			classes[statusClass(status)] += n
		}
		for _, c := range []string{"2xx", "3xx", "4xx", "5xx", "other"} {
			m.GaugeWith("ctaudit_elb_requests", "Matching requests in the last run, by ELB status class.",
				"status_class", c, float64(classes[c]))
		}
		s, cs := res.Summary, res.Conns
		m.Gauge("ctaudit_elb_received_bytes", "Bytes received from clients by matching requests.", float64(s.ReceivedBytes))
		m.Gauge("ctaudit_elb_sent_bytes", "Bytes sent to clients by matching requests.", float64(s.SentBytes))
		m.Gauge("ctaudit_elb_latency_avg_seconds", "Mean total latency of matching requests.", avg(s.LatencySum, s.LatencyCount))
		m.Gauge("ctaudit_elb_latency_max_seconds", "Highest total latency of matching requests.", s.LatencyMax)
		m.Gauge("ctaudit_elb_conns", "Matching ALB connection log records.", float64(cs.Total))
		m.Gauge("ctaudit_elb_conns_tls", "Matching connections that negotiated TLS.", float64(cs.TLS))
		m.Gauge("ctaudit_elb_tls_handshake_failed", "Matching connections whose TLS handshake failed.", float64(cs.HandshakeFailed))
		m.Gauge("ctaudit_elb_tls_handshake_avg_seconds", "Mean TLS handshake time.", avg(cs.HandshakeSum, cs.HandshakeCount))
		m.Gauge("ctaudit_elb_tls_handshake_max_seconds", "Highest TLS handshake time.", cs.HandshakeMax)
	}
}

// statusClass maps "200" to "2xx"; 1xx, "-", and anything odd are "other".
func statusClass(status string) string {
	if len(status) == 3 && status[0] >= '2' && status[0] <= '5' {
		return status[:1] + "xx"
	}
	return "other"
}

func avg(sum float64, n int) float64 {
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}
