package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/stats"
	"github.com/gsmappdev/ctaudit/internal/waflog"
	"github.com/gsmappdev/ctaudit/internal/wafrules"
)

func sampleWAFResult() (engine.WAFResult, Meta) {
	ts := time.Date(2026, 9, 23, 14, 5, 0, 0, time.UTC)
	entries := []waflog.Entry{
		{
			Time: ts, WebACL: "acl-main", Action: "BLOCK", Rule: "rule-sqli",
			RuleGroup: "AWSManagedRulesSQLiRuleSet", ClientIP: "203.0.113.9", Country: "US",
			Method: "GET", Host: "example.com", URI: "/a?b=<x>",
			UserAgent: "<script>alert(1)</script>", ResponseCode: 403, Source: "ALB",
			JA4: "ja4abc", Labels: []string{"label-xss"},
		},
		{
			Time: ts.Add(time.Minute), WebACL: "acl-main", Action: "BLOCK", Rule: "rule-sqli",
			RuleGroup: "AWSManagedRulesSQLiRuleSet", ClientIP: "203.0.113.9", Country: "US",
			Method: "POST", Host: "example.com", URI: "/login", UserAgent: "curl/7.68.0",
			ResponseCode: 403, Source: "ALB",
		},
		{
			Time: ts.Add(2 * time.Minute), WebACL: "acl-main", Action: "ALLOW",
			ClientIP: "198.51.100.5", Country: "CA", Method: "GET", Host: "example.com",
			URI: "/home", UserAgent: "Mozilla/5.0",
		},
		{
			Time: ts.Add(time.Hour), WebACL: "acl-main", Action: "COUNT",
			CountRules: []string{"geo-watch-count"}, ClientIP: "198.51.100.20", Country: "DE",
			Method: "GET", Host: "example.com", URI: "/api",
		},
		{
			Time: ts.Add(time.Hour + time.Minute), WebACL: "acl-main", Action: "BLOCK",
			RateRule: "rl-country", ClientIP: "198.51.100.20", Country: "DE",
			Method: "GET", Host: "example.com", URI: "/api",
		},
		{
			Time: ts.Add(time.Hour + 2*time.Minute), WebACL: "acl-main", Action: "BLOCK",
			RateRule: "rl-country", ClientIP: "198.51.100.21", Country: "DE",
			Method: "GET", Host: "example.com", URI: "/api",
		},
	}
	sum := stats.NewWAFSummary()
	for _, e := range entries {
		sum.Add(e)
	}
	fs, dropped := wafrules.Detect(sum, wafrules.Options{BlockThreshold: 2})

	res := engine.WAFResult{
		Summary: sum, Findings: fs, FindingsDropped: dropped, Matches: entries,
		WebACLs: []string{"acl-main"}, ObjectsScanned: 1, RecordsRead: len(entries),
		MatchedRecords: len(entries), Elapsed: 750 * time.Millisecond,
		Errors: []string{"decode AWSLogs/x.log.gz: line 3: bad"},
	}
	meta := Meta{
		Bucket: "waf-logs", Accounts: []string{"111122223333"}, Regions: []string{"us-east-1"},
		Since: ts, Until: ts, GeneratedAt: ts, Narrowed: true,
	}
	return res, meta
}

func TestWAFCountedTileUsesCountRulesNotAction(t *testing.T) {
	// The COUNT action never appears at the top level, so the "Counted"
	// tile must come from stats.WAFSummary.Counted (requests with a
	// CountRules match), not sum.ByAction["COUNT"].
	entries := []waflog.Entry{
		{Action: "ALLOW", CountRules: []string{"geo-watch"}},
		{Action: "BLOCK"},
	}
	sum := stats.NewWAFSummary()
	for _, e := range entries {
		sum.Add(e)
	}
	if sum.ByAction["COUNT"] != 0 {
		t.Fatalf("fixture must have no top-level COUNT action, got %d", sum.ByAction["COUNT"])
	}
	res := engine.WAFResult{Summary: sum, Matches: entries, WebACLs: []string{"acl"}}
	meta := Meta{Since: time.Now(), Until: time.Now(), GeneratedAt: time.Now()}

	var buf bytes.Buffer
	if err := WAFTerminal(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range strings.Split(buf.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Counted" && fields[1] == "1" {
			found = true
		}
	}
	if !found {
		t.Errorf("terminal Counted tile wrong:\n%s", buf.String())
	}

	buf.Reset()
	if err := WAFHTML(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `<div class="v">1</div><div class="k">Counted</div>`) {
		t.Errorf("HTML Counted tile wrong")
	}
}

func TestWAFTerminal(t *testing.T) {
	res, meta := sampleWAFResult()
	if len(res.Findings) == 0 {
		t.Fatal("fixture produced no findings")
	}
	var buf bytes.Buffer
	if err := WAFTerminal(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"AWS WAF Logs", "Requests", "Blocked", "Allowed", "Counted", "Block rate",
		"WEB ACLS", "TERMINATING RULES", "RULE GROUPS", "TOP BLOCKED CLIENT IPS",
		"TOP CLIENT IPS", "BLOCKED COUNTRIES", "acl-main", "rule-sqli", "ERRORS (1)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q", want)
		}
	}
	for _, f := range res.Findings {
		if !strings.Contains(out, f.Severity.String()) {
			t.Errorf("terminal output missing severity %q", f.Severity)
		}
		if !strings.Contains(out, f.Title) {
			t.Errorf("terminal output missing finding title %q", f.Title)
		}
	}
	// Tables past the first six are left to HTML/PDF.
	if strings.Contains(out, "\nHOSTS\n") {
		t.Error("terminal output should only show the first six ranked tables")
	}
}

func TestWAFHTML(t *testing.T) {
	res, meta := sampleWAFResult()
	if len(res.Findings) == 0 {
		t.Fatal("fixture produced no findings")
	}
	var buf bytes.Buffer
	if err := WAFHTML(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if strings.Contains(out, "<link") {
		t.Error("HTML contains <link")
	}
	if strings.Contains(out, `src="http`) {
		t.Error("HTML references an external src")
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("user agent was not escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped user agent not found")
	}

	for _, want := range []string{
		"Findings", "Actions over time", "Top blocked client IPs", "Terminating rules",
		"Matching requests",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing heading %q", want)
		}
	}
	for _, f := range res.Findings {
		if !strings.Contains(out, f.Title) {
			t.Errorf("HTML missing finding title %q", f.Title)
		}
	}
	for _, want := range []string{
		"Requests", "Blocked", "Allowed", "Counted", "Challenged", "Web ACLs", "Block rate",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing summary tile %q", want)
		}
	}
}

func TestWAFPDF(t *testing.T) {
	res, meta := sampleWAFResult()
	if len(res.Findings) == 0 {
		t.Fatal("fixture produced no findings")
	}
	d, err := renderWAFPDF(res, meta, 10)
	if err != nil {
		t.Fatal(err)
	}
	renderPDFBytes(t, d)
	if !drawnContains(d, "AWS WAF Logs") {
		t.Error("WAF PDF missing title")
	}
	if !drawnContains(d, "Findings") {
		t.Error("WAF PDF missing Findings heading")
	}
	found := false
	for _, f := range res.Findings {
		if drawnContains(d, f.Title) {
			found = true
			break
		}
	}
	if !found {
		t.Error("WAF PDF missing every finding title")
	}

	var buf bytes.Buffer
	if err := WAFPDF(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Error("WAFPDF output is not a PDF")
	}
}

func TestWAFPDFEmpty(t *testing.T) {
	d, err := renderWAFPDF(engine.WAFResult{}, Meta{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	renderPDFBytes(t, d)
	if !drawnContains(d, "No matching records") {
		t.Error("empty WAF PDF missing the empty-state note")
	}
}

func TestWAFTerminalStripsControlCharacters(t *testing.T) {
	res, meta := sampleWAFResult()
	res.Findings[0].Detail = "evil\x1b[31mdetail"
	res.Matches[0].URI = "/attack\x1b[31mpayload"
	var buf bytes.Buffer
	if err := WAFTerminal(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Errorf("escape sequence reached the terminal:\n%s", out)
	}
	if !strings.Contains(out, "evil [31mdetail") {
		t.Errorf("sanitized detail missing:\n%s", out)
	}
}

func TestWAFMatchingRequestsOnlyWhenNarrowed(t *testing.T) {
	res, meta := sampleWAFResult()

	meta.Narrowed = false
	out := renderWAFTerminal(t, res, meta, 10)
	if strings.Contains(out, "MATCHING REQUESTS") {
		t.Error("terminal printed matching requests without a narrowing filter")
	}

	meta.Narrowed = true
	out = renderWAFTerminal(t, res, meta, 10)
	if !strings.Contains(out, "MATCHING REQUESTS") || !strings.Contains(out, "example.com") {
		t.Errorf("terminal missing matching requests when narrowed:\n%s", out)
	}
}

func TestWAFHTMLMatchingRequestsOnlyWhenNarrowed(t *testing.T) {
	res, meta := sampleWAFResult()

	meta.Narrowed = false
	var buf bytes.Buffer
	if err := WAFHTML(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "id=\"waf-table\"") {
		t.Error("HTML printed the matching requests table without a narrowing filter")
	}
	if !strings.Contains(out, "narrowing filter") {
		t.Error("HTML missing a note explaining why requests are hidden")
	}

	meta.Narrowed = true
	buf.Reset()
	if err := WAFHTML(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "id=\"waf-table\"") {
		t.Error("HTML missing the matching requests table when narrowed")
	}
}

func renderWAFTerminal(t *testing.T, res engine.WAFResult, meta Meta, topN int) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WAFTerminal(&buf, res, meta, topN); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestWAFTone(t *testing.T) {
	cases := map[string]string{
		"BLOCK": "crit", "CAPTCHA": "warn", "CHALLENGE": "warn", "COUNT": "info", "ALLOW": "ok",
	}
	for in, want := range cases {
		if got := tone(in); got != want {
			t.Errorf("tone(%q) = %q, want %q", in, got, want)
		}
	}
}
