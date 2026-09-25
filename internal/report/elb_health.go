package report

import (
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// maxFailingShown caps the error (5xx) and warning (4xx) request tables.
const maxFailingShown = 200

// ratio returns n/d, or 0 when d is 0.
func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}

// pct formats a 0..1 fraction as a percentage.
func pct(f float64) string {
	if f > 0 && f < 0.001 {
		return "<0.1%"
	}
	return fmt.Sprintf("%.1f%%", f*100)
}

// threshold picks ok, warn, or crit for v against two limits.
func threshold(v, warn, crit float64) string {
	switch {
	case v >= crit:
		return "crit"
	case v >= warn:
		return "warn"
	}
	return "ok"
}

// healthGauges are the tiles at the top of the Health section: the
// log-side stand-ins for the CloudWatch ALB dashboard's gauges.
func healthGauges(s *stats.ELBSummary) []gauge {
	tt := s.AvgTargetTime()
	ttGauge := gauge{Title: "Target response time (avg)", Value: "-", Hint: "no target responded", Tone: "ok"}
	if tt >= 0 {
		ttGauge.Value = formatLatency(tt)
		ttGauge.Frac = tt / (2 * latencyCrit)
		ttGauge.Tone = threshold(tt, latencyWarn, latencyCrit)
		ttGauge.Hint = fmt.Sprintf("max %s · warn %s · crit %s", formatLatency(s.TargetTime.Max),
			formatLatency(latencyWarn), formatLatency(latencyCrit))
	}
	rate5 := ratio(s.Errors5xx, s.Total)
	connRate := ratio(s.TargetConnErrors, s.Total)
	bad, seen := s.Targets5xxShare()
	targetTone := "ok"
	if bad > 0 {
		targetTone = "warn"
		if bad == seen {
			targetTone = "crit"
		}
	}
	return []gauge{
		ttGauge,
		{Title: "5xx rate", Value: pct(rate5), Frac: rate5 / 0.10, Tone: threshold(rate5, 0.01, 0.05),
			Hint: fmt.Sprintf("%s of %s requests · warn 1%% · crit 5%%", groupDigits(s.Errors5xx), groupDigits(s.Total))},
		{Title: "Target connection errors", Value: groupDigits(s.TargetConnErrors), Frac: connRate / 0.05,
			Tone: threshold(connRate, 0.000001, 0.01),
			Hint: pct(connRate) + " of requests could not reach a target"},
		{Title: "Targets returning 5xx", Value: fmt.Sprintf("%d of %d", bad, seen), Frac: ratio(bad, seen),
			Tone: targetTone, Hint: "access logs carry no health checks"},
	}
}

// groupRow is one row of the target group table.
type groupRow struct {
	Name, ARN                  string
	Requests, T2xx, T4xx, T5xx int
	ELB5xx, ConnErrors         int
	Targets                    int
	Avg, Max                   float64
	Tone                       string
}

func groupRows(s *stats.ELBSummary, n int) []groupRow {
	var out []groupRow
	for _, g := range s.TopGroups(n) {
		r := groupRow{
			Name: stats.GroupName(g.ARN), ARN: g.ARN, Requests: g.Requests,
			T2xx: g.Target[2], T4xx: g.Target[4], T5xx: g.Target[5],
			ELB5xx: g.ELB5xx, ConnErrors: g.ConnErrors, Targets: len(g.Targets),
			Avg: g.TargetTime.Avg(), Max: -1,
		}
		if g.TargetTime.Count > 0 {
			r.Max = g.TargetTime.Max
		}
		r.Tone = threshold(ratio(g.ELB5xx+g.ConnErrors, g.Requests), 0.01, 0.05)
		out = append(out, r)
	}
	return out
}

// pathRow is one row of the slowest paths table. The Pct fields scale the
// meters against the slowest maximum in the table.
type pathRow struct {
	Path             string
	Count            int
	Avg, Min, Max    float64
	AvgPct, MaxPct   int
	AvgTone, MaxTone string
}

func pathRows(s *stats.ELBSummary, n int) []pathRow {
	slow := s.SlowestPaths(n)
	top := 0.0
	for _, p := range slow {
		if p.Max > top {
			top = p.Max
		}
	}
	scale := func(v float64) int {
		if top <= 0 {
			return 0
		}
		return int(v / top * 100)
	}
	out := make([]pathRow, len(slow))
	for i, p := range slow {
		out[i] = pathRow{
			Path: p.Path, Count: p.Count, Avg: p.Avg(), Min: p.Min, Max: p.Max,
			AvgPct: scale(p.Avg()), MaxPct: scale(p.Max),
			AvgTone: threshold(p.Avg(), latencyWarn, latencyCrit),
			MaxTone: threshold(p.Max, latencyWarn, latencyCrit),
		}
	}
	return out
}

// donut is a titled ring chart with its legend.
type donut struct {
	Title  string
	SVG    template.HTML
	Slices []slice
}

var paletteTones = []string{"p1", "p2", "p3", "p4", "p5", "p6"}

// counterDonut turns a counter into a ring with at most five named slices
// and an "Other" slice. tones picks a slice colour from its key; nil uses
// the palette.
func counterDonut(title string, c stats.Counter, tones func(string) string) donut {
	total := 0
	for _, v := range c {
		total += v
	}
	d := donut{Title: title}
	if total == 0 {
		return d
	}
	pairs := c.TopN(len(c))
	rest := 0
	for i, p := range pairs {
		if i >= 5 {
			rest += p.Count
			continue
		}
		tone := paletteTones[i%len(paletteTones)]
		if tones != nil {
			tone = tones(p.Key)
		}
		d.Slices = append(d.Slices, slice{Key: p.Key, Count: p.Count, Pct: ratio(p.Count, total) * 100, Tone: tone})
	}
	if rest > 0 {
		d.Slices = append(d.Slices, slice{Key: "Other", Count: rest, Pct: ratio(rest, total) * 100, Tone: "muted"})
	}
	d.SVG = donutSVG(title, d.Slices)
	return d
}

// statusClassCounter folds status codes into 2xx..5xx classes.
func statusClassCounter(c stats.Counter) stats.Counter {
	out := stats.Counter{}
	for k, v := range c {
		if len(k) == 3 && k[0] >= '1' && k[0] <= '5' {
			out[k[:1]+"xx"] += v
		} else {
			out["other"] += v
		}
	}
	return out
}

func classTone(k string) string {
	if t := tone(strings.Replace(k, "xx", "00", 1)); t != "" {
		return t
	}
	return "muted"
}

// failing splits the kept matches into 5xx and 4xx requests, each capped
// at maxFailingShown.
func failing(matches []elblog.Entry) (errs, warns []elblog.Entry, errTotal, warnTotal int) {
	for _, e := range matches {
		if len(e.ELBStatus) != 3 {
			continue
		}
		switch e.ELBStatus[0] {
		case '5':
			errTotal++
			if len(errs) < maxFailingShown {
				errs = append(errs, e)
			}
		case '4':
			warnTotal++
			if len(warns) < maxFailingShown {
				warns = append(warns, e)
			}
		}
	}
	return
}

// chartView pairs a chart's SVG with its legend for the template.
type chartView struct {
	Title  string
	SVG    template.HTML
	Legend []legendRow
	Step   string
}

func chartViews(charts []seriesChart) []chartView {
	out := make([]chartView, 0, len(charts))
	for _, c := range charts {
		out = append(out, chartView{Title: c.Title, SVG: chartSVG(c), Legend: c.Legend(), Step: stepLabel(c)})
	}
	return out
}

func stepLabel(c seriesChart) string {
	d := c.Step
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd buckets", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh buckets", int(d.Hours()))
	}
	return fmt.Sprintf("%dm buckets", int(d.Minutes()))
}
