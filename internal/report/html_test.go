package report

import (
	"bytes"
	"strings"
	"testing"
)

func renderHTML(t *testing.T, meta Meta) string {
	t.Helper()
	var buf bytes.Buffer
	if err := HTML(&buf, sampleResult(), meta, 10); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	return buf.String()
}

func TestHTMLIsSelfContained(t *testing.T) {
	out := renderHTML(t, sampleMeta())
	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Errorf("missing doctype")
	}
	for _, banned := range []string{"<script", `src="http`, `href="http`, "<link"} {
		if strings.Contains(out, banned) {
			t.Errorf("report must not reference %q", banned)
		}
	}
}

func TestHTMLSections(t *testing.T) {
	out := renderHTML(t, sampleMeta())
	for _, want := range []string{
		"org-cloudtrail-logs",
		"2026-09-14 .. 2026-09-20 (7 days)",
		"111122223333, 444455556666",
		"41,208",
		"Generated 2026-09-21T08:00:00Z",
		"Distinct principals",
		"Findings (1)",
		`class="badge sev-critical"`,
		"StopLogging on trail org-trail",
		"Top principals", "Top event names", "Top services", "Top error codes",
		"Top source IPs", "By account", "By region",
		"Activity by hour (UTC)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestHTMLBarsScaleToLargestRow(t *testing.T) {
	out := renderHTML(t, sampleMeta())
	// alice has 2 events and bob 1, so bob's bar is half of alice's.
	if !strings.Contains(out, "width:100%") || !strings.Contains(out, "width:50%") {
		t.Errorf("bar widths not proportional")
	}
}

func TestHTMLHasTwentyFourHourBuckets(t *testing.T) {
	out := renderHTML(t, sampleMeta())
	if n := strings.Count(out, `class="hour"`); n != 24 {
		t.Errorf("hour buckets = %d, want 24", n)
	}
}

func TestHTMLMatchingEventsOnlyWhenNarrowed(t *testing.T) {
	if strings.Contains(renderHTML(t, sampleMeta()), "Matching events") {
		t.Errorf("events table rendered without a narrowing filter")
	}
	meta := sampleMeta()
	meta.Narrowed = true
	out := renderHTML(t, meta)
	if !strings.Contains(out, "Matching events (showing 3 of 3)") || !strings.Contains(out, "DeleteBucketPolicy") {
		t.Errorf("events table missing")
	}
}

func TestHTMLEscapesRecordContent(t *testing.T) {
	res := sampleResult()
	res.Findings[0].Actor = `<script>alert(1)</script>`
	var buf bytes.Buffer
	if err := HTML(&buf, res, sampleMeta(), 10); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert") {
		t.Errorf("record content was not escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("escaped actor missing")
	}
}
