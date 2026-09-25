package report

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

func TestELBHTMLHealthSections(t *testing.T) {
	res, meta := sampleELBResult()
	var buf bytes.Buffer
	if err := ELBHTML(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`id="health"`, "Target response time (avg)", "5xx rate", "Target connection errors",
		"Targets returning 5xx", "1 of 2",
		`id="timeline"`, "Requests and target response time", "Responses by ELB status",
		"Target responses", "Latency (max)", `class="svgc"`, `class="gauge"`, `class="donut"`,
		`id="groups"`, "tiles/0a1b", `id="timing"`, "/v1/{n}/{n}.pbf",
		`id="failing"`, "Errors (5xx)", "Warnings (4xx)", "None in the kept matches.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Contains(out, "<link") || strings.Contains(out, "src=\"http") {
		t.Error("HTML references external resources")
	}
}

func TestELBHTMLHealthEmpty(t *testing.T) {
	_, meta := sampleELBResult()
	var buf bytes.Buffer
	if err := ELBHTML(&buf, engine.ELBResult{Summary: stats.NewELBSummary()}, meta, 10); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{`id="health"`, `id="timeline"`, `id="groups"`, `id="failing"`} {
		if strings.Contains(buf.String(), absent) {
			t.Errorf("empty report has %q", absent)
		}
	}
}

func TestELBTerminalHealth(t *testing.T) {
	res, meta := sampleELBResult()
	var buf bytes.Buffer
	if err := ELBTerminal(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"HEALTH", "5xx rate", "50.0%", "CRIT", "TARGET GROUPS", "tiles/0a1b",
		"SLOWEST PATHS", "/v1/{n}/{n}.pbf"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q", want)
		}
	}
}

func TestELBPDFHealth(t *testing.T) {
	res, meta := sampleELBResult()
	d, err := renderELBPDF(res, meta, 10)
	if err != nil {
		t.Fatal(err)
	}
	renderPDFBytes(t, d)
	for _, want := range []string{"Health", "5xx rate", "Requests and target response time", "Latency",
		"Latency (max)", "Target groups", "tiles/0a1b", "Slowest paths", "/v1/{n}/{n}.pbf"} {
		if !drawnContains(d, want) {
			t.Errorf("ELB PDF missing %q", want)
		}
	}
}

func TestTimelineStep(t *testing.T) {
	t0 := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		span time.Duration
		want time.Duration
	}{
		{2 * time.Hour, time.Minute},
		{23 * time.Hour, 5 * time.Minute},
		{2 * 24 * time.Hour, 15 * time.Minute},
		{30 * 24 * time.Hour, 6 * time.Hour},
	}
	for _, c := range cases {
		sum := stats.NewELBSummary()
		sum.Add(elblog.Entry{Time: t0, ELBStatus: "200", Latency: 0.1, TargetTime: -1})
		sum.Add(elblog.Entry{Time: t0.Add(c.span), ELBStatus: "500", Latency: 0.3, TargetTime: -1})
		step, start, buckets := timeline(sum)
		if step != c.want {
			t.Errorf("span %v: step = %v, want %v", c.span, step, c.want)
		}
		if !start.Equal(t0) || len(buckets) > maxTimelinePoints {
			t.Errorf("span %v: start %v, %d buckets", c.span, start, len(buckets))
		}
		if buckets[0] == nil || buckets[len(buckets)-1] == nil {
			t.Errorf("span %v: end buckets empty", c.span)
		}
	}
}

func TestChartSVGGaps(t *testing.T) {
	nan := math.NaN()
	c := seriesChart{
		Title: `a<b`, Start: time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC), Step: time.Minute,
		Bars:  []series{{Name: "Requests", Tone: "accent", Values: []float64{1, 0, 2, 3, 0}}},
		Lines: []series{{Name: "avg", Tone: "warn", Right: true, Values: []float64{0.1, nan, 0.2, 0.3, nan}}},
	}
	out := string(chartSVG(c))
	if !strings.Contains(out, `aria-label="a&lt;b"`) {
		t.Error("chart title not escaped")
	}
	if n := strings.Count(out, "<rect"); n != 3 {
		t.Errorf("got %d bars, want 3", n)
	}
	if strings.Count(out, "<polyline") != 1 || strings.Count(out, "<circle") != 1 {
		t.Errorf("want one line segment and one dot: %s", out)
	}
	leg := c.Legend()
	if len(leg) != 2 || leg[0].Max != "3" || leg[1].Last != "0.3" {
		t.Errorf("legend = %+v", leg)
	}
}

func TestCounterDonutOther(t *testing.T) {
	c := stats.Counter{"a": 6, "b": 5, "c": 4, "d": 3, "e": 2, "f": 1, "g": 1}
	d := counterDonut("x", c, nil)
	if len(d.Slices) != 6 || d.Slices[5].Key != "Other" || d.Slices[5].Count != 2 {
		t.Errorf("slices = %+v", d.Slices)
	}
	if empty := counterDonut("x", stats.Counter{}, nil); empty.SVG != "" || empty.Slices != nil {
		t.Error("empty counter drew a donut")
	}
}

func TestFailingSplit(t *testing.T) {
	m := []elblog.Entry{{ELBStatus: "503"}, {ELBStatus: "404"}, {ELBStatus: "200"}, {ELBStatus: "-"}, {ELBStatus: "500"}}
	errs, warns, et, wt := failing(m)
	if len(errs) != 2 || len(warns) != 1 || et != 2 || wt != 1 {
		t.Errorf("failing = %d %d %d %d", len(errs), len(warns), et, wt)
	}
}
