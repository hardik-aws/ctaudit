package main

import (
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

var stateT0 = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

func ctTick(objects, read, matched int, sev map[findings.Severity]int) tickResult {
	sum := stats.NewSummary()
	sum.WriteEvents = matched
	return tickResult{CT: &engine.Result{
		Summary:        sum,
		ObjectsScanned: objects,
		RecordsRead:    read,
		MatchedRecords: matched,
		SeverityCounts: sev,
	}}
}

func TestServeStateSeenAfterCommitOnly(t *testing.T) {
	s := newServeState("cloudtrail", 15*time.Minute, 24*time.Hour)
	s.fail(stateT0, time.Second)
	if s.isSeen("a") {
		t.Fatal("key seen after fail")
	}
	s.commit(stateT0, ctTick(1, 1, 1, nil), []string{"a"}, 0, time.Second)
	if !s.isSeen("a") {
		t.Fatal("key not seen after commit")
	}
	if s.isSeen("b") {
		t.Fatal("unread key reported seen")
	}
}

func TestServeStateCommitKeepsFirstReadTime(t *testing.T) {
	lookback := 24 * time.Hour
	s := newServeState("cloudtrail", 15*time.Minute, lookback)
	s.commit(stateT0, ctTick(1, 1, 1, nil), []string{"a"}, 0, 0)
	s.commit(stateT0.Add(10*time.Hour), ctTick(1, 1, 1, nil), []string{"a"}, 0, 0)
	s.prune(stateT0.Add(lookback + seenRetention + time.Second))
	if s.isSeen("a") {
		t.Fatal("recommitting a key must not refresh its first-read time")
	}
}

func TestServeStatePruneKeys(t *testing.T) {
	lookback := 24 * time.Hour
	s := newServeState("cloudtrail", 15*time.Minute, lookback)
	s.commit(stateT0, ctTick(1, 1, 1, nil), []string{"old"}, 0, 0)
	s.commit(stateT0.Add(time.Hour+time.Second), ctTick(1, 1, 1, nil), []string{"new"}, 0, 0)

	now := stateT0.Add(lookback + seenRetention + time.Second)
	s.prune(now)
	if s.isSeen("old") {
		t.Error("key older than lookback+48h survived prune")
	}
	// "new" was read lookback+47h-1s before now.
	if !s.isSeen("new") {
		t.Error("key younger than lookback+48h was pruned")
	}
}

func TestServeStatePruneTicks(t *testing.T) {
	lookback := 2 * time.Hour
	s := newServeState("cloudtrail", 15*time.Minute, lookback)
	s.commit(stateT0, ctTick(1, 1, 1, nil), nil, 0, 0)
	s.commit(stateT0.Add(time.Hour), ctTick(2, 2, 2, nil), nil, 0, 0)
	s.prune(stateT0.Add(lookback + time.Second))
	snap := s.snapshot()
	if len(snap) != 1 || snap[0].CT.ObjectsScanned != 2 {
		t.Fatalf("snapshot after prune = %+v, want only the second tick", snap)
	}
}

func TestServeStateMetricsFromZero(t *testing.T) {
	s := newServeState("cloudtrail", 15*time.Minute, 24*time.Hour)
	text := s.metrics().Text()
	for _, want := range []string{
		"# TYPE ctaudit_scans_total counter",
		`ctaudit_scans_total{result="failed",subcommand="cloudtrail"} 0`,
		`ctaudit_findings_total{severity="critical",subcommand="cloudtrail"} 0`,
		`ctaudit_findings_total{severity="low",subcommand="cloudtrail"} 0`,
		`ctaudit_interval_seconds{subcommand="cloudtrail"} 900`,
		`ctaudit_lookback_seconds{subcommand="cloudtrail"} 86400`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "ctaudit_last_success_timestamp_seconds") {
		t.Error("last success gauge present before any ok tick")
	}
	if strings.Contains(text, "ctaudit_elb_") {
		t.Error("cloudtrail state renders ELB families")
	}
}

func TestServeStateMetricsSumCommits(t *testing.T) {
	s := newServeState("cloudtrail", 15*time.Minute, 24*time.Hour)
	s.commit(stateT0, ctTick(2, 10, 3, map[findings.Severity]int{findings.SevCritical: 1}), []string{"a", "b"}, 0, time.Second)
	s.commit(stateT0.Add(15*time.Minute), ctTick(1, 5, 2, map[findings.Severity]int{findings.SevCritical: 2, findings.SevLow: 1}), []string{"c"}, 1, 2*time.Second)
	s.fail(stateT0.Add(30*time.Minute), 3*time.Second)

	text := s.metrics().Text()
	for _, want := range []string{
		`ctaudit_scans_total{result="ok",subcommand="cloudtrail"} 1`,
		`ctaudit_scans_total{result="partial",subcommand="cloudtrail"} 1`,
		`ctaudit_scans_total{result="failed",subcommand="cloudtrail"} 1`,
		`ctaudit_objects_scanned_total{subcommand="cloudtrail"} 3`,
		`ctaudit_records_read_total{subcommand="cloudtrail"} 15`,
		`ctaudit_records_matched_total{subcommand="cloudtrail"} 5`,
		`ctaudit_scan_errors_total{subcommand="cloudtrail"} 1`,
		`ctaudit_findings_total{severity="critical",subcommand="cloudtrail"} 3`,
		`ctaudit_findings_total{severity="low",subcommand="cloudtrail"} 1`,
		`ctaudit_cloudtrail_write_events_total{subcommand="cloudtrail"} 5`,
		`ctaudit_seen_keys{subcommand="cloudtrail"} 3`,
		`ctaudit_scan_duration_seconds{subcommand="cloudtrail"} 3`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q:\n%s", want, text)
		}
	}
	// Only the first tick was ok, so last success stays at stateT0.
	if !strings.Contains(text, "ctaudit_last_success_timestamp_seconds") {
		t.Error("last success gauge missing after an ok tick")
	}
}

func TestServeStateELBMetrics(t *testing.T) {
	s := newServeState("elb", time.Minute, time.Hour)
	sum := stats.NewELBSummary()
	sum.ByStatus["200"] = 4
	sum.ByStatus["503"] = 1
	sum.ByStatus["-"] = 2
	sum.LatencySum, sum.LatencyCount = 1.5, 3
	conns := stats.NewConnSummary()
	conns.Total, conns.TLS, conns.HandshakeFailed = 3, 2, 1
	s.commit(stateT0, tickResult{ELB: &engine.ELBResult{
		Summary: sum, Conns: conns, RecordsRead: 7, ConnsRead: 3, MatchedRecords: 7, MatchedConns: 3, ObjectsScanned: 2,
	}}, []string{"x"}, 0, 0)

	text := s.metrics().Text()
	for _, want := range []string{
		`ctaudit_elb_requests_total{status_class="2xx",subcommand="elb"} 4`,
		`ctaudit_elb_requests_total{status_class="5xx",subcommand="elb"} 1`,
		`ctaudit_elb_requests_total{status_class="other",subcommand="elb"} 2`,
		`ctaudit_elb_requests_total{status_class="3xx",subcommand="elb"} 0`,
		`ctaudit_elb_latency_seconds_sum{subcommand="elb"} 1.5`,
		`ctaudit_elb_latency_seconds_count{subcommand="elb"} 3`,
		`ctaudit_elb_conns_total{subcommand="elb"} 3`,
		`ctaudit_elb_conns_tls_total{subcommand="elb"} 2`,
		`ctaudit_elb_tls_handshake_failed_total{subcommand="elb"} 1`,
		`ctaudit_records_read_total{subcommand="elb"} 10`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "ctaudit_findings_total") {
		t.Error("elb state renders findings")
	}
}
