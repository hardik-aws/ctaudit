package wafrules

import (
	"fmt"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

func TestDetectExploit(t *testing.T) {
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.Exploits["203.0.113.9"] = &stats.ExploitHit{
		Count:   2,
		First:   time.Unix(200, 0),
		URI:     "/login",
		Matches: stats.Counter{"AWSManagedRulesSQLiRuleSet/SQLi_BODY": 2},
	}

	fs, dropped := Detect(s, Options{})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if dropped != 0 {
		t.Fatalf("got %d dropped, want 0", dropped)
	}

	f := fs[0]
	if f.Rule != "waf-exploit-allowed" {
		t.Errorf("Rule = %q, want waf-exploit-allowed", f.Rule)
	}
	if f.Severity != findings.SevCritical {
		t.Errorf("Severity = %v, want SevCritical", f.Severity)
	}
	if f.Actor != "203.0.113.9" {
		t.Errorf("Actor = %q, want 203.0.113.9", f.Actor)
	}
	if f.Time != time.Unix(200, 0) {
		t.Errorf("Time = %v, want 200", f.Time)
	}
	if f.Title != "Exploit payload allowed" {
		t.Errorf("Title = %q", f.Title)
	}
	if !contains(f.Detail, "/login") || !contains(f.Detail, "SQLi_BODY") {
		t.Errorf("Detail = %q, should contain /login and SQLi_BODY", f.Detail)
	}
}

func TestDetectAttackerAllowed(t *testing.T) {
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.IPs["1.1.1.1"] = &stats.IPStats{Blocks: 100, Allows: 1}

	fs, _ := Detect(s, Options{BlockThreshold: 100})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}

	f := fs[0]
	if f.Rule != "waf-attacker-allowed" {
		t.Errorf("Rule = %q, want waf-attacker-allowed", f.Rule)
	}
	if f.Severity != findings.SevHigh {
		t.Errorf("Severity = %v, want SevHigh", f.Severity)
	}
	if f.Actor != "1.1.1.1" {
		t.Errorf("Actor = %q, want 1.1.1.1", f.Actor)
	}
}

func TestDetectAttackerAllowedBelowThreshold(t *testing.T) {
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.IPs["1.1.1.1"] = &stats.IPStats{Blocks: 99, Allows: 1}

	fs, _ := Detect(s, Options{BlockThreshold: 100})
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func TestDetectPersistentBlockedIP(t *testing.T) {
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.IPs["1.1.1.1"] = &stats.IPStats{Blocks: 150, Allows: 0}

	fs, _ := Detect(s, Options{BlockThreshold: 100})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}

	f := fs[0]
	if f.Rule != "waf-persistent-blocked-ip" {
		t.Errorf("Rule = %q, want waf-persistent-blocked-ip", f.Rule)
	}
	if f.Severity != findings.SevMedium {
		t.Errorf("Severity = %v, want SevMedium", f.Severity)
	}
}

func TestDetectPersistentNotAttackerAllowed(t *testing.T) {
	// When Blocks >= threshold and Allows == 0, should get waf-persistent-blocked-ip only
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.IPs["1.1.1.1"] = &stats.IPStats{Blocks: 150, Allows: 0}

	fs, _ := Detect(s, Options{BlockThreshold: 100})

	var rules []string
	for _, f := range fs {
		rules = append(rules, f.Rule)
	}
	if len(rules) != 1 || rules[0] != "waf-persistent-blocked-ip" {
		t.Errorf("got rules %v, want [waf-persistent-blocked-ip]", rules)
	}
}

func TestDetectRateLimited(t *testing.T) {
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.RateByRule["rl"] = stats.Counter{"1.1.1.1": 5, "2.2.2.2": 9}

	fs, _ := Detect(s, Options{})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}

	f := fs[0]
	if f.Rule != "waf-rate-limited" {
		t.Errorf("Rule = %q, want waf-rate-limited", f.Rule)
	}
	if f.Severity != findings.SevHigh {
		t.Errorf("Severity = %v, want SevHigh", f.Severity)
	}
	if f.Actor != "rl" {
		t.Errorf("Actor = %q, want rl", f.Actor)
	}
	if !contains(f.Detail, "2.2.2.2") || !contains(f.Detail, "1.1.1.1") || !contains(f.Detail, "14") {
		t.Errorf("Detail = %q, should contain both IPs and total 14", f.Detail)
	}
	// Check that 2.2.2.2 appears before 1.1.1.1 in detail (top IPs listed first)
	pos2 := indexOf(f.Detail, "2.2.2.2")
	pos1 := indexOf(f.Detail, "1.1.1.1")
	if pos2 >= pos1 {
		t.Errorf("2.2.2.2 should appear before 1.1.1.1 in detail")
	}
}

func TestDetectCountRule(t *testing.T) {
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.ByCountRule["geo-watch"] = 7

	fs, _ := Detect(s, Options{})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}

	f := fs[0]
	if f.Rule != "waf-count-rule" {
		t.Errorf("Rule = %q, want waf-count-rule", f.Rule)
	}
	if f.Severity != findings.SevMedium {
		t.Errorf("Severity = %v, want SevMedium", f.Severity)
	}
	if f.Actor != "geo-watch" {
		t.Errorf("Actor = %q, want geo-watch", f.Actor)
	}
}

func TestDetectOversize(t *testing.T) {
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.Oversize = 3

	fs, _ := Detect(s, Options{})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}

	f := fs[0]
	if f.Rule != "waf-oversize" {
		t.Errorf("Rule = %q, want waf-oversize", f.Rule)
	}
	if f.Severity != findings.SevMedium {
		t.Errorf("Severity = %v, want SevMedium", f.Severity)
	}
	if f.Actor != "" {
		t.Errorf("Actor = %q, want empty", f.Actor)
	}
}

func TestDetectChallengeFails(t *testing.T) {
	// With threshold 100, min = 10
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.IPs["1.1.1.1"] = &stats.IPStats{ChallengeFails: 10}

	fs, _ := Detect(s, Options{BlockThreshold: 100})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}

	f := fs[0]
	if f.Rule != "waf-challenge-failures" {
		t.Errorf("Rule = %q, want waf-challenge-failures", f.Rule)
	}
	if f.Severity != findings.SevLow {
		t.Errorf("Severity = %v, want SevLow", f.Severity)
	}
}

func TestDetectChallengeFailsBelowMin(t *testing.T) {
	// With threshold 100, min = 10; 9 should not trigger
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.IPs["1.1.1.1"] = &stats.IPStats{ChallengeFails: 9}

	fs, _ := Detect(s, Options{BlockThreshold: 100})
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func TestDetectChallengeFailsSmallThreshold(t *testing.T) {
	// With threshold 5, min = 1
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.IPs["1.1.1.1"] = &stats.IPStats{ChallengeFails: 1}

	fs, _ := Detect(s, Options{BlockThreshold: 5})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}

	f := fs[0]
	if f.Rule != "waf-challenge-failures" {
		t.Errorf("Rule = %q, want waf-challenge-failures", f.Rule)
	}
}

func TestDetectCap(t *testing.T) {
	// 3 exploits (CRITICAL) and 5 persistent IPs (MEDIUM)
	// With Max: 2, all 3 CRITICAL should be kept, no MEDIUM, dropped == 5
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)

	// Add 3 critical findings
	for i := 1; i <= 3; i++ {
		ip := "203.0.113." + string(rune(48+i))
		s.Exploits[ip] = &stats.ExploitHit{
			Count:   1,
			First:   time.Unix(int64(200+i), 0),
			URI:     "/payload",
			Matches: stats.Counter{"rule": 1},
		}
	}

	// Add 5 medium findings
	for i := 1; i <= 5; i++ {
		ip := "1.1.1." + string(rune(48+i))
		s.IPs[ip] = &stats.IPStats{Blocks: 150, Allows: 0}
	}

	fs, dropped := Detect(s, Options{Max: 2, BlockThreshold: 100})

	// All 3 CRITICAL should be kept
	var criticals int
	var mediums int
	for _, f := range fs {
		if f.Severity == findings.SevCritical {
			criticals++
		} else if f.Severity == findings.SevMedium {
			mediums++
		}
	}

	if criticals != 3 {
		t.Errorf("got %d CRITICAL findings, want 3", criticals)
	}
	if mediums != 0 {
		t.Errorf("got %d MEDIUM findings, want 0", mediums)
	}
	if dropped != 5 {
		t.Errorf("got %d dropped, want 5", dropped)
	}
}

func TestDetectSorting(t *testing.T) {
	// Test sorting: by severity descending, then count descending, then actor, then rule
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)

	// Add CRITICAL: exploit with 5 requests
	s.Exploits["203.0.113.1"] = &stats.ExploitHit{
		Count:   5,
		First:   time.Unix(200, 0),
		URI:     "/",
		Matches: stats.Counter{"rule": 5},
	}

	// Add CRITICAL: exploit with 3 requests
	s.Exploits["203.0.113.2"] = &stats.ExploitHit{
		Count:   3,
		First:   time.Unix(200, 0),
		URI:     "/",
		Matches: stats.Counter{"rule": 3},
	}

	// Add HIGH findings
	s.IPs["1.1.1.1"] = &stats.IPStats{Blocks: 100, Allows: 1}
	s.IPs["1.1.1.2"] = &stats.IPStats{Blocks: 100, Allows: 1}

	fs, _ := Detect(s, Options{BlockThreshold: 100})

	// Should have 4 findings: 2 CRITICAL, 2 HIGH
	if len(fs) != 4 {
		t.Fatalf("got %d findings, want 4", len(fs))
	}

	// Check ordering
	if fs[0].Severity != findings.SevCritical || fs[0].Rule != "waf-exploit-allowed" {
		t.Errorf("first finding should be CRITICAL exploit")
	}
	// Exploits are sorted by count desc, so 5 should come before 3
	if fs[0].Detail != fs[1].Detail {
		// Both are exploits but with different counts
		// The one with 5 should come first
		if !contains(fs[0].Detail, "5") {
			t.Errorf("first exploit should have count 5, got detail: %s", fs[0].Detail)
		}
	}

	// All CRITICAL findings should come before HIGH
	var seenHigh bool
	for _, f := range fs {
		if f.Severity == findings.SevHigh {
			seenHigh = true
		} else if seenHigh && f.Severity < findings.SevHigh {
			t.Errorf("found non-HIGH/non-CRITICAL after HIGH")
		}
	}
}

func TestMaxSeverity(t *testing.T) {
	tests := []struct {
		name string
		fs   []findings.Finding
		sev  findings.Severity
		ok   bool
	}{
		{
			name: "empty",
			fs:   []findings.Finding{},
			sev:  findings.SevLow,
			ok:   false,
		},
		{
			name: "single low",
			fs:   []findings.Finding{{Severity: findings.SevLow}},
			sev:  findings.SevLow,
			ok:   true,
		},
		{
			name: "mixed",
			fs: []findings.Finding{
				{Severity: findings.SevLow},
				{Severity: findings.SevCritical},
				{Severity: findings.SevMedium},
			},
			sev: findings.SevCritical,
			ok:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sev, ok := MaxSeverity(tt.fs)
			if ok != tt.ok {
				t.Errorf("MaxSeverity ok = %v, want %v", ok, tt.ok)
			}
			if sev != tt.sev {
				t.Errorf("MaxSeverity sev = %v, want %v", sev, tt.sev)
			}
		})
	}
}

func TestDefaultBlockThreshold(t *testing.T) {
	// Zero BlockThreshold should mean 100
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)
	s.IPs["1.1.1.1"] = &stats.IPStats{Blocks: 100, Allows: 1}

	fs, _ := Detect(s, Options{}) // BlockThreshold: 0
	if len(fs) != 1 || fs[0].Rule != "waf-attacker-allowed" {
		t.Errorf("zero BlockThreshold should default to 100")
	}
}

func TestDefaultMax(t *testing.T) {
	// Zero Max should mean 500
	s := stats.NewWAFSummary()
	s.First = time.Unix(100, 0)

	// Add 600 MEDIUM findings (persistent blocked IPs)
	for i := 1; i <= 600; i++ {
		ip := ipFromNum(i)
		s.IPs[ip] = &stats.IPStats{Blocks: 100, Allows: 0}
	}

	fs, dropped := Detect(s, Options{BlockThreshold: 100}) // Max: 0
	if len(fs)+dropped != 600 {
		t.Errorf("got %d findings + %d dropped = %d, want 600", len(fs), dropped, len(fs)+dropped)
	}
	if len(fs) != 500 {
		t.Errorf("zero Max should default to 500, got %d", len(fs))
	}
	if dropped != 100 {
		t.Errorf("expected 100 dropped, got %d", dropped)
	}
}

// helpers

func contains(s, substr string) bool {
	return indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func ipFromNum(i int) string {
	a := (i - 1) / (256 * 256)
	b := ((i - 1) / 256) % 256
	c := (i - 1) % 256
	return fmt.Sprintf("10.%d.%d.%d", a, b, c)
}
