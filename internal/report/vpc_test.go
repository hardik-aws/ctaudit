package report

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/flowlog"
	"github.com/gsmappdev/ctaudit/internal/stats"
	"github.com/gsmappdev/ctaudit/internal/vpcrules"
)

func sampleVPCResult() (engine.VPCResult, Meta) {
	ts := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	mk := func(src, dst string, sp, dp int, action string, b int64, at time.Time) flowlog.Entry {
		return flowlog.Entry{
			Version: 5, InterfaceID: "eni-<script>alert(1)</script>", VPCID: "vpc-0123456789abcdef0",
			SrcAddr: netip.MustParseAddr(src), DstAddr: netip.MustParseAddr(dst), SrcPort: sp, DstPort: dp,
			Protocol: 6, Packets: 3, Bytes: b, Start: at, End: at.Add(time.Minute), Action: action,
			LogStatus: flowlog.StatusOK, TCPFlags: -1, TrafficPath: -1, FlowDirection: "ingress",
		}
	}
	entries := []flowlog.Entry{
		mk("203.0.113.9", "10.0.1.10", 40001, 22, "REJECT", 40, ts),
		mk("203.0.113.9", "10.0.1.10", 40002, 23, "REJECT", 40, ts.Add(time.Minute)),
		mk("203.0.113.50", "10.0.1.20", 50505, 22, "ACCEPT", 7200, ts.Add(time.Hour)),
		mk("198.51.100.7", "10.0.1.10", 51544, 443, "ACCEPT", 5120, ts.Add(time.Hour+time.Minute)),
	}
	entries[0].RejectReason = "<b>x</b>"
	rules := vpcrules.Options{ScanPorts: 2}
	sum := stats.NewVPCSummary(rules.Limits())
	for _, e := range entries {
		sum.Add(e)
	}
	sum.AddStatus(flowlog.StatusSkipData)
	fs, dropped := vpcrules.Detect(sum, rules)
	res := engine.VPCResult{
		Summary: sum, Findings: fs, FindingsDropped: dropped, Matches: entries,
		ObjectsScanned: 1, RecordsRead: len(entries) + 1, MatchedRecords: len(entries),
		Errors: []string{"decode k: 1 unparseable lines, first: bad dstaddr field"}, Elapsed: 2 * time.Second,
	}
	meta := Meta{
		Bucket: "example-flow-logs", Accounts: []string{"111122223333"}, Regions: []string{"us-east-1"},
		Since: ts.Truncate(24 * time.Hour), Until: ts.Truncate(24 * time.Hour), Narrowed: true, GeneratedAt: ts,
	}
	return res, meta
}

func TestVPCTerminal(t *testing.T) {
	res, meta := sampleVPCResult()
	var buf bytes.Buffer
	if err := VPCTerminal(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"VPC Flow Logs", "TRAFFIC", "Reject rate", "50.0%", "SKIPDATA", "FINDINGS (", "Port scan from a public address",
		"Sensitive port reachable from the internet", "BYTES BY ACTION", "12.0 KiB", "TOP SOURCES",
		"MATCHING FLOWS (showing 4 of 4)", "ERRORS (1)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal missing %q:\n%s", want, out)
		}
	}
}

func TestVPCHTML(t *testing.T) {
	res, meta := sampleVPCResult()
	if len(res.Findings) == 0 {
		t.Fatal("fixture produced no findings")
	}
	var buf bytes.Buffer
	if err := VPCHTML(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<link") || strings.Contains(out, `src="http`) {
		t.Error("HTML is not self-contained")
	}
	if strings.Contains(out, "<script>alert(1)</script>") || !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("interface ID was not escaped")
	}
	if strings.Contains(out, "<b>x</b>") || !strings.Contains(out, "&lt;b&gt;x&lt;/b&gt;") {
		t.Error("reject reason was not escaped")
	}
	if !strings.Contains(out, "Reject reason") {
		t.Error("HTML missing the reject reason column header")
	}
	for _, want := range []string{
		"Findings", "Flows over time", "Top sources", "Bytes by action", "Top pairs by bytes", "Matching flows",
		"Flows", "Bytes", "Packets", "Accepted", "Rejected", "Reject rate", "Interfaces", "SKIPDATA", "12.0 KiB",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	for _, f := range res.Findings {
		if !strings.Contains(out, f.Title) {
			t.Errorf("HTML missing finding %q", f.Title)
		}
	}
	// Protocol 6 is named "tcp" by flowlog.ProtocolName, not a bare 3-digit
	// number, so give the ranked-table pill guard its own direct coverage:
	// a 3-digit key that is not ACCEPT/REJECT must never become a pill.
	if got := actionTone("200"); got != "" {
		t.Errorf("actionTone(%q) = %q, want empty (no pill for non-action keys)", "200", got)
	}
	if got := actionTone("REJECT"); got != "crit" {
		t.Errorf("actionTone(REJECT) = %q, want crit", got)
	}
	if got := actionTone("ACCEPT"); got != "ok" {
		t.Errorf("actionTone(ACCEPT) = %q, want ok", got)
	}
}

func TestVPCHTMLNotNarrowed(t *testing.T) {
	res, meta := sampleVPCResult()
	meta.Narrowed = false
	var buf bytes.Buffer
	if err := VPCHTML(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `id="vpc-table"`) || !strings.Contains(buf.String(), "--src-cidr") {
		t.Error("flow table shown without a narrowing filter")
	}
}

func TestVPCPDF(t *testing.T) {
	res, meta := sampleVPCResult()
	d, err := renderVPCPDF(res, meta, 10)
	if err != nil {
		t.Fatal(err)
	}
	renderPDFBytes(t, d)
	for _, want := range []string{"VPC Flow Logs", "Findings", "Bytes by action", "12.0 KiB", res.Findings[0].Rule} {
		if !drawnContains(d, want) {
			t.Errorf("PDF missing %q", want)
		}
	}
	var buf bytes.Buffer
	if err := VPCPDF(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Error("VPCPDF output is not a PDF")
	}
}

func TestVPCPDFEmpty(t *testing.T) {
	d, err := renderVPCPDF(engine.VPCResult{}, Meta{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	renderPDFBytes(t, d)
	if !drawnContains(d, "No matching flows") {
		t.Error("empty VPC PDF missing the empty-state note")
	}
}

func TestVPCTone(t *testing.T) {
	if tone("REJECT") != "crit" || tone("ACCEPT") != "ok" {
		t.Fatalf("tone REJECT=%q ACCEPT=%q", tone("REJECT"), tone("ACCEPT"))
	}
}
