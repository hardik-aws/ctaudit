package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

func sampleELBResult() (engine.ELBResult, Meta) {
	ts := time.Date(2026, 9, 23, 14, 5, 0, 0, time.UTC)
	entries := []elblog.Entry{
		{
			Kind: elblog.ALB, Type: "https", Time: ts, LB: "app/tiles/abc",
			ClientIP: "203.0.113.9", ClientPort: "51000", Target: "10.0.1.5:8080",
			RequestTime: 0.001, TargetTime: 0.120, ResponseTime: 0, Latency: 0.121,
			ELBStatus: "200", TargetStatus: "200", ReceivedBytes: 512, SentBytes: 4096,
			Method: "GET", URL: "https://tiles.example.com:443/v1/12/6346.pbf",
			Host: "tiles.example.com", Path: "/v1/12/6346.pbf",
			UserAgent: "<script>alert(1)</script>", SSLCipher: "ECDHE-RSA-AES128-GCM-SHA256",
			SSLProtocol: "TLSv1.2", Actions: "forward",
			TargetGroupARN: "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/tiles/0a1b",
		},
		{
			Kind: elblog.ALB, Type: "https", Time: ts.Add(time.Hour), LB: "app/tiles/abc",
			ClientIP: "198.51.100.7", Latency: -1, RequestTime: -1, TargetTime: -1, ResponseTime: -1,
			ELBStatus: "502", Method: "GET", Path: "/v1/health", ErrorReason: "TargetConnectionError",
			Target: "10.0.1.6:8080", TargetGroupARN: "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/tiles/0a1b",
		},
	}
	sum := stats.NewELBSummary()
	for _, e := range entries {
		sum.Add(e)
	}
	conns := []elblog.Entry{
		{
			Kind: elblog.ALB, Conn: true, Time: ts, LB: "app/tiles/abc",
			ClientIP: "203.0.113.9", ClientPort: "51000", Listener: "443",
			SSLProtocol: "TLSv1.3", SSLCipher: "TLS_AES_128_GCM_SHA256", TLSKeyExchange: "X25519",
			TLSHandshakeTime: 0.004, TLSVerifyStatus: "Success", ConnTraceID: "TID_abc",
		},
		{
			Kind: elblog.ALB, Conn: true, Time: ts.Add(time.Minute), LB: "app/tiles/abc",
			ClientIP: "198.18.71.40", ClientPort: "40000", Listener: "443",
			TLSHandshakeTime: -1, ConnTraceID: "TID_def",
		},
	}
	connSum := stats.NewConnSummary()
	for _, e := range conns {
		connSum.Add(e)
	}
	res := engine.ELBResult{
		Summary: sum, Matches: entries, ObjectsScanned: 1,
		RecordsRead: 2, MatchedRecords: 2, Elapsed: 1500 * time.Millisecond,
		Conns: connSum, ConnMatches: conns, ConnsRead: 2, MatchedConns: 2,
		Errors: []string{"decode AWSLogs/x.log.gz: line 3: bad"},
	}
	meta := Meta{
		Bucket: "logs", Accounts: []string{"111122223333"}, Regions: []string{"us-east-1"},
		Since: ts, Until: ts, GeneratedAt: ts,
	}
	return res, meta
}

func TestELBTerminal(t *testing.T) {
	res, meta := sampleELBResult()
	var buf bytes.Buffer
	if err := ELBTerminal(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"ELB Access Logs", "TRAFFIC", "4.0 KiB", "BY LOAD BALANCER", "app/tiles/abc",
		"/v1/{n}/{n}.pbf", "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", "TargetConnectionError",
		"REQUESTS BY HOUR (UTC)", "  14", "ERRORS (1)", "Connections read: 2",
		"TLS CONNECTIONS", "CONNECTIONS BY TLS CIPHER", "TLS_AES_128_GCM_SHA256",
		"443 TLSv1.3", "443 no TLS", "TOP FAILED HANDSHAKE CLIENT IPS", "198.18.71.40",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q", want)
		}
	}
	if strings.Contains(out, "MATCHING REQUESTS") || strings.Contains(out, "MATCHING CONNECTIONS") {
		t.Error("matching rows shown although scan was not narrowed")
	}

	meta.Narrowed = true
	buf.Reset()
	if err := ELBTerminal(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MATCHING REQUESTS (showing 2 of 2)", "MATCHING CONNECTIONS (showing 2 of 2)", "FAILED"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("narrowed terminal output missing %q", want)
		}
	}
}

func TestELBHTML(t *testing.T) {
	res, meta := sampleELBResult()
	var buf bytes.Buffer
	if err := ELBHTML(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"<style>", "ELB Access Logs", "Top client IPs", "By TLS cipher",
		"Requests (showing 2 of 2, earliest first)", "TargetConnectionError", "121 ms",
		"tiles.example.com", "&lt;script&gt;", "TLS key exchange", "Target status list",
		"TLS connections", "Failed TLS handshakes (443)", "By listener and TLS protocol",
		"Connections (showing 2 of 2, earliest first)", "X25519", "4.0 ms",
		"handshake failed", "TID_def",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Contains(out, "<script>alert") || !strings.Contains(out, "&lt;script&gt;alert(1)") {
		t.Error("user agent was not escaped")
	}
	for _, want := range []string{`pill crit`, `data-peak`, `data-filter="req-table"`, `data-filter="conn-table"`, `id="req-wrap"`} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Contains(out, "<link") || strings.Contains(out, "src=\"http") {
		t.Error("HTML references external resources")
	}
	if n := strings.Count(out, `class="hour"`); n != 24 {
		t.Errorf("got %d hour buckets, want 24", n)
	}
}

func TestELBHTMLNilSummary(t *testing.T) {
	_, meta := sampleELBResult()
	var buf bytes.Buffer
	if err := ELBHTML(&buf, engine.ELBResult{}, meta, 10); err != nil {
		t.Fatal(err)
	}
	if err := ELBTerminal(&buf, engine.ELBResult{}, meta, 10); err != nil {
		t.Fatal(err)
	}
}

func TestTone(t *testing.T) {
	cases := map[string]string{
		"200": "ok", "302": "info", "404": "warn", "502": "crit", "-": "",
		"TLSv1.3": "ok", "TLSv1.2": "", "443 TLSv1.3": "ok", "443 TLSv1": "crit", "443 TLSv1.1": "crit",
		"443 no TLS": "crit", "443 unknown": "warn", "Success": "ok", "FailedCertValidation": "crit",
		"GET": "", "tiles.example.com": "",
	}
	for in, want := range cases {
		if got := tone(in); got != want {
			t.Errorf("tone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 30: "5.0 GiB"}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatLatency(t *testing.T) {
	cases := map[float64]string{-1: "-", 0.0005: "0.5 ms", 0.121: "121 ms", 12.5: "12.5 s"}
	for in, want := range cases {
		if got := formatLatency(in); got != want {
			t.Errorf("formatLatency(%v) = %q, want %q", in, got, want)
		}
	}
}
