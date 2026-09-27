package vpcrules

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/flowlog"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

var t0 = time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)

func flow(src, dst string, sp, dp int, action string, bytes int64) flowlog.Entry {
	return flowlog.Entry{
		SrcAddr: netip.MustParseAddr(src), DstAddr: netip.MustParseAddr(dst), SrcPort: sp, DstPort: dp,
		Protocol: 6, Packets: 1, Bytes: bytes, Start: t0, Action: action, LogStatus: flowlog.StatusOK,
		TCPFlags: -1, TrafficPath: -1,
	}
}

func byRule(fs []findings.Finding, rule string) []findings.Finding {
	var out []findings.Finding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func TestPortScan(t *testing.T) {
	o := Options{ScanPorts: 3}
	s := stats.NewVPCSummary(o.Limits())
	for _, p := range []int{22, 23, 3389, 8080} {
		s.Add(flow("203.0.113.9", "10.0.1.10", 40000, p, "REJECT", 40))
	}
	for _, p := range []int{22, 23} { // below threshold
		s.Add(flow("203.0.113.10", "10.0.1.10", 40000, p, "REJECT", 40))
	}
	fs, dropped := Detect(s, o)
	got := byRule(fs, "vpc-port-scan")
	if dropped != 0 || len(got) != 1 {
		t.Fatalf("port scan findings = %+v", got)
	}
	f := got[0]
	if f.Severity != findings.SevHigh || f.Actor != "203.0.113.9" || f.Title != "Port scan from a public address" ||
		!strings.Contains(f.Detail, "3 or more distinct ports") || !strings.Contains(f.Detail, "4 rejected flows") ||
		!f.Time.Equal(t0) {
		t.Fatalf("finding %+v", f)
	}
}

func TestSensitivePortExposed(t *testing.T) {
	s := stats.NewVPCSummary(Options{}.Limits())
	for i := range 7 {
		s.Add(flow(fmt.Sprintf("192.0.2.%d", i+1), "10.0.1.5", 60000, 22, "ACCEPT", 1024))
	}
	s.Add(flow("192.0.2.1", "10.0.1.5", 60000, 22, "ACCEPT", 1024))
	got := byRule(only(Detect(s, Options{})), "vpc-sensitive-port-exposed")
	if len(got) != 1 {
		t.Fatalf("findings %+v", got)
	}
	f := got[0]
	if f.Severity != findings.SevHigh || f.Actor != "10.0.1.5:22/tcp" ||
		!strings.Contains(f.Detail, "8 accepted flows") || !strings.Contains(f.Detail, "8.0 KiB") ||
		!strings.Contains(f.Detail, "from 7 public sources") || !strings.Contains(f.Detail, "192.0.2.1 (2)") {
		t.Fatalf("finding %+v", f)
	}
	if strings.Count(f.Detail, "192.0.2.") != 5 {
		t.Fatalf("detail should list the top 5 sources: %s", f.Detail)
	}
}

func TestHostSweep(t *testing.T) {
	o := Options{SweepHosts: 3}
	s := stats.NewVPCSummary(o.Limits())
	// Reaching exactly the threshold
	for i := range 3 {
		s.Add(flow("10.0.9.9", fmt.Sprintf("10.0.1.%d", i+1), 50000, 22, "REJECT", 40))
	}
	// Just below the threshold: 2 distinct private addresses
	for i := range 2 {
		s.Add(flow("10.0.7.7", fmt.Sprintf("10.0.2.%d", i+1), 50000, 22, "REJECT", 40))
	}
	// Replies from 10.0.8.8: source port below destination port (return traffic, not initiator)
	for i := range 3 {
		s.Add(flow("10.0.8.8", fmt.Sprintf("10.0.1.%d", i+1), 443, 50000, "ACCEPT", 40))
	}
	got := byRule(only(Detect(s, o)), "vpc-host-sweep")
	if len(got) != 1 || got[0].Actor != "10.0.9.9" || got[0].Severity != findings.SevMedium ||
		!strings.Contains(got[0].Detail, "3 or more distinct private addresses") {
		t.Fatalf("findings %+v", got)
	}
}

func TestLargeEgress(t *testing.T) {
	o := Options{EgressBytes: 1000}
	s := stats.NewVPCSummary(o.Limits())
	s.Add(flow("10.0.1.30", "198.51.100.200", 49152, 443, "ACCEPT", 600))
	s.Add(flow("10.0.1.30", "198.51.100.201", 49153, 443, "ACCEPT", 400))
	s.Add(flow("10.0.1.31", "198.51.100.200", 49152, 443, "ACCEPT", 999))
	got := byRule(only(Detect(s, o)), "vpc-large-egress")
	if len(got) != 1 || got[0].Actor != "10.0.1.30" || got[0].Severity != findings.SevMedium ||
		!strings.Contains(got[0].Detail, "1000 B") {
		t.Fatalf("findings %+v", got)
	}
}

func TestLegacyProtocol(t *testing.T) {
	s := stats.NewVPCSummary(Options{}.Limits())
	s.Add(flow("203.0.113.5", "10.0.1.6", 50000, 23, "ACCEPT", 10))
	s.Add(flow("203.0.113.5", "10.0.1.6", 50001, 23, "ACCEPT", 10))
	s.Add(flow("10.0.1.7", "203.0.113.6", 50000, 445, "ACCEPT", 10))
	got := byRule(only(Detect(s, Options{})), "vpc-legacy-protocol")
	if len(got) != 2 {
		t.Fatalf("findings %+v", got)
	}
	// Sorted by count: the telnet host (2 flows) comes first.
	if got[0].Actor != "10.0.1.6" || !strings.Contains(got[0].Detail, "2 accepted flows on 23/tcp inbound from public addresses") ||
		got[1].Actor != "10.0.1.7" || !strings.Contains(got[1].Detail, "outbound to public addresses") ||
		got[0].Severity != findings.SevLow {
		t.Fatalf("findings %+v", got)
	}
}

func TestDetectOrderAndCap(t *testing.T) {
	o := Options{ScanPorts: 2, Max: 2}
	s := stats.NewVPCSummary(o.Limits())
	s.Add(flow("203.0.113.5", "10.0.1.6", 50000, 23, "ACCEPT", 10)) // LOW
	s.Add(flow("192.0.2.1", "10.0.1.5", 60000, 22, "ACCEPT", 10))   // HIGH exposed, 2 flows
	s.Add(flow("192.0.2.2", "10.0.1.5", 60001, 22, "ACCEPT", 10))
	for _, p := range []int{1, 2} { // HIGH scan
		s.Add(flow("203.0.113.9", "10.0.1.10", 40000, p, "REJECT", 40))
	}
	fs, dropped := Detect(s, o)
	if len(fs) != 2 || dropped != 1 {
		t.Fatalf("got %d findings, dropped %d", len(fs), dropped)
	}
	for _, f := range fs {
		if f.Severity != findings.SevHigh {
			t.Fatalf("cap kept a lower severity first: %+v", fs)
		}
	}
	// Equal severity and count (2 each): actor ascending.
	if fs[0].Actor != "10.0.1.5:22/tcp" || fs[1].Actor != "203.0.113.9" {
		t.Fatalf("order %q, %q", fs[0].Actor, fs[1].Actor)
	}
}

func TestDefaults(t *testing.T) {
	l := Options{}.Limits()
	if l.ScanPorts != stats.DefaultScanPorts || l.SweepHosts != stats.DefaultSweepHosts {
		t.Fatalf("limits %+v", l)
	}
	s := stats.NewVPCSummary(l)
	for p := range 24 {
		s.Add(flow("203.0.113.9", "10.0.1.10", 40000, p+1, "REJECT", 40))
	}
	if got := byRule(only(Detect(s, Options{})), "vpc-port-scan"); len(got) != 0 {
		t.Fatal("24 ports must stay below the default 25")
	}
	s.Add(flow("203.0.113.9", "10.0.1.10", 40000, 25, "REJECT", 40))
	if got := byRule(only(Detect(s, Options{})), "vpc-port-scan"); len(got) != 1 {
		t.Fatal("25 ports must reach the default threshold")
	}
}

func TestMaxSeverity(t *testing.T) {
	if _, ok := MaxSeverity(nil); ok {
		t.Fatal("empty should report false")
	}
	sev, ok := MaxSeverity([]findings.Finding{{Severity: findings.SevLow}, {Severity: findings.SevHigh}, {Severity: findings.SevMedium}})
	if !ok || sev != findings.SevHigh {
		t.Fatalf("MaxSeverity = %v, %v", sev, ok)
	}
}

// only drops the dropped count for tests that do not check it.
func only(fs []findings.Finding, _ int) []findings.Finding { return fs }
