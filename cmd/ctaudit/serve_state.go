package main

import (
	"strings"
	"sync"
	"time"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/sink"
)

// seenRetention is how long past the lookback a key stays in the seen set.
// Objects are filed under their delivery day and the scope scans one extra
// day, so a key can be listed again for up to a day after the window moves
// past it; two days leaves margin.
const seenRetention = 48 * time.Hour

var (
	scanResults   = []string{"ok", "partial", "failed"}
	severities    = []findings.Severity{findings.SevLow, findings.SevMedium, findings.SevHigh, findings.SevCritical}
	statusClasses = []string{"2xx", "3xx", "4xx", "5xx", "other"}
)

// tickResult is one committed tick. Exactly one of CT and ELB is set.
type tickResult struct {
	At  time.Time
	CT  *engine.Result
	ELB *engine.ELBResult
}

// serveTotals holds the counters that only ever grow.
type serveTotals struct {
	scans          map[string]int
	objects        int
	read           int
	matched        int
	errors         int
	severity       map[findings.Severity]int
	writeEvents    int
	errorEvents    int
	statusClass    map[string]int
	receivedBytes  int64
	sentBytes      int64
	latencySum     float64
	latencyCount   int
	conns          int
	connsTLS       int
	handshakeFail  int
	handshakeSum   float64
	handshakeCount int
}

// serveState is everything serve keeps between ticks: which object keys
// were already read, the running counters, and the committed ticks inside
// the lookback that /report merges. Every method takes the mutex, so the
// tick loop and HTTP handlers can share one value.
type serveState struct {
	mu       sync.Mutex
	sub      string
	interval time.Duration
	lookback time.Duration
	seen     map[string]time.Time
	totals   serveTotals
	ticks    []tickResult

	lastScan     time.Time
	lastSuccess  time.Time
	lastDuration time.Duration
}

func newServeState(sub string, interval, lookback time.Duration) *serveState {
	return &serveState{
		sub:      sub,
		interval: interval,
		lookback: lookback,
		seen:     map[string]time.Time{},
		totals: serveTotals{
			scans:       map[string]int{},
			severity:    map[findings.Severity]int{},
			statusClass: map[string]int{},
		},
	}
}

// isSeen reports whether key was read by a committed tick. The engine calls
// it from its list workers.
func (s *serveState) isSeen(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.seen[key]
	return ok
}

// commit records a tick whose lines were delivered: its keys become seen,
// its counts are added to the totals, and its result is kept for /report.
// errs is the number of objects that could not be read.
func (s *serveState) commit(now time.Time, t tickResult, readKeys []string, errs int, dur time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, k := range readKeys {
		if _, ok := s.seen[k]; !ok {
			s.seen[k] = now
		}
	}

	tot := &s.totals
	tot.errors += errs
	if ct := t.CT; ct != nil {
		tot.objects += ct.ObjectsScanned
		tot.read += ct.RecordsRead
		tot.matched += ct.MatchedRecords
		for sev, n := range ct.SeverityCounts {
			tot.severity[sev] += n
		}
		if ct.Summary != nil {
			tot.writeEvents += ct.Summary.WriteEvents
			tot.errorEvents += ct.Summary.ErrorEvents
		}
	}
	if e := t.ELB; e != nil {
		tot.objects += e.ObjectsScanned
		tot.read += e.RecordsRead + e.ConnsRead
		tot.matched += e.MatchedRecords + e.MatchedConns
		if sum := e.Summary; sum != nil {
			for status, n := range sum.ByStatus {
				tot.statusClass[statusClass(status)] += n
			}
			tot.receivedBytes += sum.ReceivedBytes
			tot.sentBytes += sum.SentBytes
			tot.latencySum += sum.LatencySum
			tot.latencyCount += sum.LatencyCount
		}
		if c := e.Conns; c != nil {
			tot.conns += c.Total
			tot.connsTLS += c.TLS
			tot.handshakeFail += c.HandshakeFailed
			tot.handshakeSum += c.HandshakeSum
			tot.handshakeCount += c.HandshakeCount
		}
	}

	t.At = now
	s.ticks = append(s.ticks, t)
	s.lastScan = now
	s.lastDuration = dur
	if errs == 0 {
		tot.scans["ok"]++
		s.lastSuccess = now
	} else {
		tot.scans["partial"]++
	}
}

// fail records a tick that committed nothing: no keys become seen, so the
// next tick reads the same objects again.
func (s *serveState) fail(now time.Time, dur time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totals.scans["failed"]++
	s.lastScan = now
	s.lastDuration = dur
}

// prune forgets seen keys older than lookback plus seenRetention and ticks
// older than lookback, and reports how many of each it dropped.
func (s *serveState) prune(now time.Time) (keys, ticks int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keyCutoff := now.Add(-(s.lookback + seenRetention))
	for k, at := range s.seen {
		if at.Before(keyCutoff) {
			delete(s.seen, k)
			keys++
		}
	}
	tickCutoff := now.Add(-s.lookback)
	kept := s.ticks[:0]
	for _, t := range s.ticks {
		if !t.At.Before(tickCutoff) {
			kept = append(kept, t)
		}
	}
	ticks = len(s.ticks) - len(kept)
	for i := len(kept); i < len(s.ticks); i++ {
		s.ticks[i] = tickResult{}
	}
	s.ticks = kept
	return keys, ticks
}

// seenCount is the number of remembered keys.
func (s *serveState) seenCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// snapshot returns a copy of the committed ticks inside the lookback.
func (s *serveState) snapshot() []tickResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]tickResult, len(s.ticks))
	copy(out, s.ticks)
	return out
}

// metrics renders the current counters and gauges. Every family carries a
// subcommand label, and every result, severity, and status class appears
// from zero so rate() and increase() work from the first scrape.
func (s *serveState) metrics() *sink.Metrics {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := sink.NewMetrics()
	sub := s.sub
	one := func(name, help string, v float64, typ string) {
		labels := map[string]string{"subcommand": sub}
		if typ == "counter" {
			m.CounterLabels(name, help, labels, v)
		} else {
			m.GaugeLabels(name, help, labels, v)
		}
	}
	with := func(name, help, label, value string, v float64) {
		m.CounterLabels(name, help, map[string]string{"subcommand": sub, label: value}, v)
	}
	tot := s.totals

	for _, r := range scanResults {
		with("ctaudit_scans_total", "Scan ticks by result.", "result", r, float64(tot.scans[r]))
	}
	one("ctaudit_objects_scanned_total", "Log objects read by committed ticks.", float64(tot.objects), "counter")
	one("ctaudit_records_read_total", "Records read by committed ticks.", float64(tot.read), "counter")
	one("ctaudit_records_matched_total", "Records that matched the filters in committed ticks.", float64(tot.matched), "counter")
	one("ctaudit_scan_errors_total", "Objects that could not be read in committed ticks.", float64(tot.errors), "counter")

	switch sub {
	case "cloudtrail":
		for _, sev := range severities {
			with("ctaudit_findings_total", "Rule hits by severity, including hits past the findings cap.", "severity", strings.ToLower(sev.String()), float64(tot.severity[sev]))
		}
		one("ctaudit_cloudtrail_write_events_total", "Matching CloudTrail events that were not read-only.", float64(tot.writeEvents), "counter")
		one("ctaudit_cloudtrail_error_events_total", "Matching CloudTrail events with an error code.", float64(tot.errorEvents), "counter")
	case "elb":
		for _, c := range statusClasses {
			with("ctaudit_elb_requests_total", "Matching requests by ELB status class.", "status_class", c, float64(tot.statusClass[c]))
		}
		one("ctaudit_elb_received_bytes_total", "Bytes received from clients by matching requests.", float64(tot.receivedBytes), "counter")
		one("ctaudit_elb_sent_bytes_total", "Bytes sent to clients by matching requests.", float64(tot.sentBytes), "counter")
		one("ctaudit_elb_latency_seconds_sum", "Sum of measurable request latency in seconds.", tot.latencySum, "counter")
		one("ctaudit_elb_latency_seconds_count", "Requests with a measurable latency.", float64(tot.latencyCount), "counter")
		one("ctaudit_elb_conns_total", "Matching ALB connection log records.", float64(tot.conns), "counter")
		one("ctaudit_elb_conns_tls_total", "Matching connections that negotiated TLS.", float64(tot.connsTLS), "counter")
		one("ctaudit_elb_tls_handshake_failed_total", "Matching connections whose TLS handshake failed.", float64(tot.handshakeFail), "counter")
		one("ctaudit_elb_tls_handshake_seconds_sum", "Sum of measured TLS handshake time in seconds.", tot.handshakeSum, "counter")
		one("ctaudit_elb_tls_handshake_seconds_count", "Connections with a measured TLS handshake time.", float64(tot.handshakeCount), "counter")
	}

	if !s.lastScan.IsZero() {
		one("ctaudit_last_scan_timestamp_seconds", "Unix time the last tick finished.", unixSeconds(s.lastScan), "gauge")
		one("ctaudit_scan_duration_seconds", "Wall time of the last tick in seconds.", s.lastDuration.Seconds(), "gauge")
	}
	if !s.lastSuccess.IsZero() {
		one("ctaudit_last_success_timestamp_seconds", "Unix time of the last tick that committed without errors.", unixSeconds(s.lastSuccess), "gauge")
	}
	one("ctaudit_seen_keys", "Object keys remembered as already read.", float64(len(s.seen)), "gauge")
	one("ctaudit_lookback_seconds", "Configured lookback in seconds.", s.lookback.Seconds(), "gauge")
	one("ctaudit_interval_seconds", "Configured tick interval in seconds.", s.interval.Seconds(), "gauge")
	return m
}

func unixSeconds(t time.Time) float64 {
	return float64(t.UnixNano()) / 1e9
}
