package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func rec(actor, event, errCode string, at time.Time) ctevent.Record {
	return ctevent.Record{
		EventTime:          at,
		EventSource:        "s3.amazonaws.com",
		EventName:          event,
		AWSRegion:          "us-east-1",
		SourceIPAddress:    "203.0.113.44",
		ErrorCode:          errCode,
		RecipientAccountID: "111122223333",
		UserIdentity:       ctevent.UserIdentity{ARN: actor},
	}
}

// sampleResult builds a Result by hand so report tests need no engine run.
func sampleResult() engine.Result {
	at := time.Date(2026, 9, 19, 14, 19, 2, 0, time.UTC)
	recs := []ctevent.Record{
		rec("arn:aws:iam::111122223333:user/alice", "DeleteBucket", "", at),
		rec("arn:aws:iam::111122223333:user/alice", "DeleteBucketPolicy", "", at.Add(time.Minute)),
		rec("arn:aws:iam::111122223333:user/bob", "GetObject", "AccessDenied", at.Add(2*time.Minute)),
	}
	sum := stats.NewSummary()
	for _, r := range recs {
		sum.Add(r)
	}
	return engine.Result{
		Summary: sum,
		Findings: []findings.Finding{{
			Rule:     "cloudtrail-tamper",
			Severity: findings.SevCritical,
			Title:    "CloudTrail tampering",
			Actor:    "arn:aws:iam::111122223333:user/alice",
			Account:  "111122223333",
			Region:   "us-east-1",
			EventID:  "ev-1",
			Detail:   "StopLogging on trail org-trail",
			Time:     at,
		}},
		Matches:        recs,
		ObjectsScanned: 41208,
		RecordsRead:    3914660,
		MatchedRecords: 3,
		Elapsed:        4*time.Minute + 12*time.Second,
	}
}

func sampleMeta() Meta {
	return Meta{
		Bucket:      "org-cloudtrail-logs",
		Accounts:    []string{"111122223333", "444455556666"},
		Regions:     []string{"us-east-1", "eu-central-1"},
		Since:       day("2026-09-14"),
		Until:       day("2026-09-20"),
		GeneratedAt: time.Date(2026, 9, 21, 8, 0, 0, 0, time.UTC),
	}
}

func renderTerminal(t *testing.T, res engine.Result, meta Meta, topN int) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Terminal(&buf, res, meta, topN); err != nil {
		t.Fatalf("Terminal: %v", err)
	}
	return buf.String()
}

func TestTerminalHeader(t *testing.T) {
	out := renderTerminal(t, sampleResult(), sampleMeta(), 10)
	for _, want := range []string{
		"CloudTrail Audit — 2026-09-14 .. 2026-09-20 (7 days)",
		"Bucket: org-cloudtrail-logs",
		"Accounts: 2",
		"Regions: 2",
		"Objects scanned: 41,208",
		"Records read: 3,914,660",
		"Matched: 3",
		"Elapsed: 4m12s",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

func TestTerminalSummaryAndTables(t *testing.T) {
	out := renderTerminal(t, sampleResult(), sampleMeta(), 10)
	for _, want := range []string{
		"SUMMARY", "Total events", "Write events", "Error events",
		"First event", "2026-09-19T14:19:02Z",
		"TOP PRINCIPALS", "TOP EVENTS", "TOP SERVICES", "TOP ERROR CODES",
		"TOP SOURCE IPS", "BY ACCOUNT", "BY REGION",
		"AccessDenied", "203.0.113.44",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestTerminalTopNLimitsRows(t *testing.T) {
	out := renderTerminal(t, sampleResult(), sampleMeta(), 1)
	section := out[strings.Index(out, "TOP PRINCIPALS"):strings.Index(out, "TOP EVENTS")]
	if !strings.Contains(section, "user/alice") {
		t.Errorf("top principal alice missing:\n%s", section)
	}
	if strings.Contains(section, "user/bob") {
		t.Errorf("topN=1 should hide bob:\n%s", section)
	}
}

func TestTerminalFindings(t *testing.T) {
	res := sampleResult()
	res.DroppedFindings = 4
	out := renderTerminal(t, res, sampleMeta(), 10)
	for _, want := range []string{"FINDINGS (1)", "CRITICAL", "cloudtrail-tamper", "StopLogging on trail org-trail", "4 further findings dropped"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}

	res.Findings = nil
	res.DroppedFindings = 0
	out = renderTerminal(t, res, sampleMeta(), 10)
	if !strings.Contains(out, "FINDINGS (0)") || !strings.Contains(out, "none") {
		t.Errorf("empty findings section wrong:\n%s", out)
	}
}

func TestTerminalMatchingEventsOnlyWhenNarrowed(t *testing.T) {
	meta := sampleMeta()
	if out := renderTerminal(t, sampleResult(), meta, 10); strings.Contains(out, "MATCHING EVENTS") {
		t.Errorf("events table printed without a narrowing filter")
	}

	meta.Narrowed = true
	out := renderTerminal(t, sampleResult(), meta, 10)
	for _, want := range []string{"MATCHING EVENTS (showing 3 of 3)", "DeleteBucketPolicy", "EVENT NAME"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestTerminalErrors(t *testing.T) {
	res := sampleResult()
	for i := 0; i < 12; i++ {
		res.Errors = append(res.Errors, "get key: AccessDenied")
	}
	out := renderTerminal(t, res, sampleMeta(), 10)
	if !strings.Contains(out, "ERRORS (12)") || !strings.Contains(out, "... 2 more") {
		t.Errorf("errors section wrong:\n%s", out)
	}
}

func TestTerminalStripsControlCharacters(t *testing.T) {
	res := sampleResult()
	res.Findings[0].Actor = "evil\x1b[2J\tactor\nx"
	out := renderTerminal(t, res, sampleMeta(), 10)
	if strings.Contains(out, "\x1b") {
		t.Errorf("escape sequence reached the terminal")
	}
	if !strings.Contains(out, "evil [2J actor x") {
		t.Errorf("sanitized actor missing:\n%s", out)
	}
}

func TestTerminalNilSummary(t *testing.T) {
	renderTerminal(t, engine.Result{}, sampleMeta(), 10)
}

func TestGroupDigits(t *testing.T) {
	cases := map[int]string{0: "0", 7: "7", 999: "999", 1000: "1,000", 41208: "41,208", 3914660: "3,914,660", -1234: "-1,234"}
	for in, want := range cases {
		if got := groupDigits(in); got != want {
			t.Errorf("groupDigits(%d) = %q, want %q", in, got, want)
		}
	}
}
