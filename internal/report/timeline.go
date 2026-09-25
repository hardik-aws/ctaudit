package report

import (
	"math"
	"sort"
	"time"

	"github.com/gsmappdev/ctaudit/internal/stats"
)

// maxTimelinePoints caps the buckets in one chart; the step grows until the
// span fits.
const maxTimelinePoints = 288

var timelineSteps = []time.Duration{
	time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour,
}

// Latency guide lines, in seconds, drawn on the latency charts and used to
// colour the target response time gauge.
const (
	latencyWarn = 0.5
	latencyCrit = 1.0
)

// series is one drawn series. Values holds one value per bucket; NaN means
// no data (a gap in a line). Tone picks the colour: ok, info, warn, crit,
// accent, or muted.
type series struct {
	Name   string
	Tone   string
	Values []float64
	// Right puts a line on the right-hand axis.
	Right bool
}

// guide is a horizontal reference line on the left axis.
type guide struct {
	Value float64
	Tone  string
	Label string
}

// seriesChart is a time chart: stacked bars and lines over shared buckets.
type seriesChart struct {
	Title string
	// Seconds marks an axis whose values are durations; the other axis
	// holds counts. LeftSeconds applies to bars and left lines,
	// RightSeconds to right lines.
	LeftSeconds, RightSeconds bool
	Start                     time.Time
	Step                      time.Duration
	Bars                      []series
	Lines                     []series
	Guides                    []guide
}

// Len returns the number of buckets.
func (c seriesChart) Len() int {
	for _, s := range append(append([]series{}, c.Bars...), c.Lines...) {
		return len(s.Values)
	}
	return 0
}

// legendRow is the min/max/avg/last summary of one series.
type legendRow struct {
	Name, Tone          string
	Min, Max, Avg, Last string
	MinV, MaxV, AvgV    float64
	seconds, hasSamples bool
}

// Legend summarises every series of the chart, bars first.
func (c seriesChart) Legend() []legendRow {
	var out []legendRow
	add := func(s series, seconds bool) {
		r := legendRow{Name: s.Name, Tone: s.Tone, seconds: seconds}
		n, sum, last := 0, 0.0, math.NaN()
		for _, v := range s.Values {
			if math.IsNaN(v) {
				continue
			}
			if n == 0 || v < r.MinV {
				r.MinV = v
			}
			if n == 0 || v > r.MaxV {
				r.MaxV = v
			}
			n++
			sum += v
			last = v
		}
		fmtv := func(v float64) string {
			if math.IsNaN(v) {
				return "-"
			}
			if seconds {
				return formatLatency(v)
			}
			if v == math.Trunc(v) {
				return groupDigits(int(v))
			}
			return formatFloat(v)
		}
		if n > 0 {
			r.hasSamples = true
			r.AvgV = sum / float64(n)
			r.Min, r.Max, r.Avg, r.Last = fmtv(r.MinV), fmtv(r.MaxV), fmtv(r.AvgV), fmtv(last)
		} else {
			r.Min, r.Max, r.Avg, r.Last = "-", "-", "-", "-"
		}
		out = append(out, r)
	}
	for _, s := range c.Bars {
		add(s, c.LeftSeconds)
	}
	for _, s := range c.Lines {
		add(s, (s.Right && c.RightSeconds) || (!s.Right && c.LeftSeconds))
	}
	return out
}

// timeline re-buckets the per-minute aggregates into at most
// maxTimelinePoints buckets and returns the step, the first bucket start,
// and the merged buckets (nil entries for empty buckets).
func timeline(sum *stats.ELBSummary) (time.Duration, time.Time, []*stats.TimeBucket) {
	if len(sum.Timeline) == 0 {
		return 0, time.Time{}, nil
	}
	minutes := make([]int64, 0, len(sum.Timeline))
	for m := range sum.Timeline {
		minutes = append(minutes, m)
	}
	sort.Slice(minutes, func(i, j int) bool { return minutes[i] < minutes[j] })
	first, last := minutes[0], minutes[len(minutes)-1]

	step := timelineSteps[len(timelineSteps)-1]
	for _, s := range timelineSteps {
		per := int64(s / time.Minute)
		if (last/per-first/per)+1 <= maxTimelinePoints {
			step = s
			break
		}
	}
	per := int64(step / time.Minute)
	base := first / per
	buckets := make([]*stats.TimeBucket, last/per-base+1)
	for _, m := range minutes {
		i := m/per - base
		if buckets[i] == nil {
			buckets[i] = &stats.TimeBucket{}
		}
		buckets[i].Merge(sum.Timeline[m])
	}
	return step, time.Unix(base*per*60, 0).UTC(), buckets
}

// elbCharts builds the timeline charts of the ELB report. It returns nil
// when no request carried a time.
func elbCharts(sum *stats.ELBSummary) []seriesChart {
	step, start, buckets := timeline(sum)
	if len(buckets) == 0 {
		return nil
	}
	col := func(f func(b *stats.TimeBucket) float64, zero float64) []float64 {
		out := make([]float64, len(buckets))
		for i, b := range buckets {
			if b == nil {
				out[i] = zero
				continue
			}
			out[i] = f(b)
		}
		return out
	}
	count := func(f func(b *stats.TimeBucket) int) []float64 {
		return col(func(b *stats.TimeBucket) float64 { return float64(f(b)) }, 0)
	}
	avg := func(f func(b *stats.TimeBucket) stats.LatStat) []float64 {
		return col(func(b *stats.TimeBucket) float64 {
			if v := f(b).Avg(); v >= 0 {
				return v
			}
			return math.NaN()
		}, math.NaN())
	}
	maxOf := func(f func(b *stats.TimeBucket) stats.LatStat) []float64 {
		return col(func(b *stats.TimeBucket) float64 {
			if l := f(b); l.Count > 0 {
				return l.Max
			}
			return math.NaN()
		}, math.NaN())
	}
	classes := func(get func(b *stats.TimeBucket) [6]int, from int, none string) []series {
		names := []string{"", "1xx", "2xx", "3xx", "4xx", "5xx"}
		tones := []string{"muted", "info", "ok", "info", "warn", "crit"}
		var out []series
		if none != "" {
			v := count(func(b *stats.TimeBucket) int { a := get(b); return a[0] + a[1] })
			if nonZero(v) {
				out = append(out, series{Name: none, Tone: "muted", Values: v})
			}
		}
		for c := from; c <= 5; c++ {
			c := c
			v := count(func(b *stats.TimeBucket) int { return get(b)[c] })
			if nonZero(v) {
				out = append(out, series{Name: names[c], Tone: tones[c], Values: v})
			}
		}
		return out
	}
	elbStatus := func(b *stats.TimeBucket) [6]int { return b.ELB }
	targetStatus := func(b *stats.TimeBucket) [6]int { return b.Target }
	targetTime := func(b *stats.TimeBucket) stats.LatStat { return b.TargetTime }
	lat := func(b *stats.TimeBucket) stats.LatStat { return b.Latency }

	charts := []seriesChart{
		{
			Title: "Requests and target response time", RightSeconds: true,
			Bars:  []series{{Name: "Requests", Tone: "accent", Values: count(func(b *stats.TimeBucket) int { return b.Requests })}},
			Lines: []series{{Name: "Target response time (avg)", Tone: "warn", Right: true, Values: avg(targetTime)}},
		},
		{Title: "Responses by ELB status", Bars: classes(elbStatus, 2, "Other")},
		{
			Title: "Target responses",
			Bars:  classes(targetStatus, 2, "No target response"),
			Lines: []series{{Name: "Target connection errors", Tone: "crit",
				Values: count(func(b *stats.TimeBucket) int { return b.ConnErrors })}},
		},
		{
			Title: "Latency", LeftSeconds: true,
			Lines: []series{
				{Name: "Latency (avg)", Tone: "accent", Values: avg(lat)},
				{Name: "Latency (max)", Tone: "crit", Values: maxOf(lat)},
				{Name: "Target response time (avg)", Tone: "warn", Values: avg(targetTime)},
			},
			Guides: []guide{
				{Value: latencyWarn, Tone: "warn", Label: formatLatency(latencyWarn)},
				{Value: latencyCrit, Tone: "crit", Label: formatLatency(latencyCrit)},
			},
		},
	}
	for i := range charts {
		charts[i].Start, charts[i].Step = start, step
	}
	return charts
}

func nonZero(v []float64) bool {
	for _, x := range v {
		if x != 0 && !math.IsNaN(x) {
			return true
		}
	}
	return false
}
