package report

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"strconv"
	"strings"
	"time"
)

// The ELB report draws its charts as inline SVG so the page needs no script
// library. Colours come from CSS classes (s-ok, s-crit, …) that read the
// theme tokens, so the charts follow light and dark mode.

const (
	svgW      = 960.0
	svgH      = 230.0
	svgLeft   = 58.0
	svgRight  = 58.0
	svgTop    = 12.0
	svgBottom = 24.0
)

// formatFloat renders a non-integer count compactly.
func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// niceMax rounds v up to 1, 2, 2.5, or 5 times a power of ten.
func niceMax(v float64) float64 {
	if v <= 0 || math.IsNaN(v) {
		return 1
	}
	p := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if v <= m*p {
			return m * p
		}
	}
	return 10 * p
}

// axisLabel formats one tick value.
func axisLabel(v float64, seconds bool) string {
	if seconds {
		return formatLatency(v)
	}
	switch {
	case v >= 1e6:
		return strconv.FormatFloat(v/1e6, 'f', -1, 64) + "M"
	case v >= 1e3:
		return strconv.FormatFloat(v/1e3, 'f', -1, 64) + "k"
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// timeLabel formats a bucket start for the x axis.
func timeLabel(t time.Time, step time.Duration, multiDay bool) string {
	switch {
	case step >= 24*time.Hour:
		return t.Format("01-02")
	case multiDay:
		return t.Format("01-02 15:04")
	}
	return t.Format("15:04")
}

// chartSVG draws c: stacked bars and lines on the left axis, lines on the
// right axis, and guide lines.
func chartSVG(c seriesChart) template.HTML {
	n := c.Len()
	if n == 0 {
		return ""
	}
	hasRight := false
	for _, l := range c.Lines {
		hasRight = hasRight || l.Right
	}
	right := svgRight
	if !hasRight {
		right = 16
	}
	plotW := svgW - svgLeft - right
	plotH := svgH - svgTop - svgBottom
	slot := plotW / float64(n)

	// Axis ranges.
	leftMax, rightMax := 0.0, 0.0
	for i := 0; i < n; i++ {
		stack := 0.0
		for _, b := range c.Bars {
			stack += b.Values[i]
		}
		leftMax = math.Max(leftMax, stack)
	}
	for _, l := range c.Lines {
		for _, v := range l.Values {
			if math.IsNaN(v) {
				continue
			}
			if l.Right {
				rightMax = math.Max(rightMax, v)
			} else {
				leftMax = math.Max(leftMax, v)
			}
		}
	}
	for _, g := range c.Guides {
		leftMax = math.Max(leftMax, g.Value)
	}
	leftMax, rightMax = niceMax(leftMax), niceMax(rightMax)
	yl := func(v float64) float64 { return svgTop + plotH - v/leftMax*plotH }
	yr := func(v float64) float64 { return svgTop + plotH - v/rightMax*plotH }

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="svgc" viewBox="0 0 %.0f %.0f" role="img" aria-label="%s">`,
		svgW, svgH, html.EscapeString(c.Title))

	// Grid and axis labels.
	for i := 0; i <= 4; i++ {
		f := float64(i) / 4
		y := svgTop + plotH - f*plotH
		fmt.Fprintf(&b, `<line class="gl" x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f"/>`, svgLeft, svgLeft+plotW, y, y)
		fmt.Fprintf(&b, `<text class="ax" x="%.1f" y="%.1f" text-anchor="end">%s</text>`,
			svgLeft-6, y+4, axisLabel(f*leftMax, c.LeftSeconds))
		if hasRight {
			fmt.Fprintf(&b, `<text class="ax" x="%.1f" y="%.1f">%s</text>`,
				svgLeft+plotW+6, y+4, axisLabel(f*rightMax, c.RightSeconds))
		}
	}
	end := c.Start.Add(time.Duration(n) * c.Step)
	multiDay := end.Sub(c.Start) > 24*time.Hour || c.Start.YearDay() != end.Add(-time.Second).YearDay()
	ticks := 6
	if n < ticks {
		ticks = n
	}
	for i := 0; i < ticks; i++ {
		idx := i * n / ticks
		x := svgLeft + (float64(idx)+0.5)*slot
		t := c.Start.Add(time.Duration(idx) * c.Step)
		fmt.Fprintf(&b, `<text class="ax" x="%.1f" y="%.1f" text-anchor="middle">%s</text>`,
			x, svgH-6, timeLabel(t, c.Step, multiDay))
	}

	// Stacked bars; one group per bucket carries the tooltip.
	if len(c.Bars) > 0 {
		bw := math.Max(slot*0.8, 1)
		for i := 0; i < n; i++ {
			total := 0.0
			for _, s := range c.Bars {
				total += s.Values[i]
			}
			if total == 0 {
				continue
			}
			t := c.Start.Add(time.Duration(i) * c.Step)
			var tip strings.Builder
			tip.WriteString(t.Format("2006-01-02 15:04"))
			fmt.Fprintf(&b, `<g>`)
			base := 0.0
			for _, s := range c.Bars {
				v := s.Values[i]
				if v <= 0 {
					continue
				}
				y0, y1 := yl(base), yl(base+v)
				fmt.Fprintf(&b, `<rect class="s-%s" x="%.2f" y="%.2f" width="%.2f" height="%.2f"/>`,
					s.Tone, svgLeft+float64(i)*slot+(slot-bw)/2, y1, bw, math.Max(y0-y1, 0.5))
				fmt.Fprintf(&tip, "\n%s: %s", s.Name, axisLabel(v, c.LeftSeconds))
				base += v
			}
			fmt.Fprintf(&b, `<title>%s</title></g>`, html.EscapeString(tip.String()))
		}
	}

	// Guides.
	for _, g := range c.Guides {
		y := yl(g.Value)
		fmt.Fprintf(&b, `<line class="guide l-%s" x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f"/>`,
			g.Tone, svgLeft, svgLeft+plotW, y, y)
		fmt.Fprintf(&b, `<text class="ax t-%s" x="%.1f" y="%.1f" text-anchor="end">%s</text>`,
			g.Tone, svgLeft+plotW-4, y-4, html.EscapeString(g.Label))
	}

	// Lines, broken at gaps. A lone point is drawn as a dot.
	for _, l := range c.Lines {
		y := yl
		if l.Right {
			y = yr
		}
		var seg []string
		flush := func() {
			switch len(seg) {
			case 0:
			case 1:
				xy := strings.Split(seg[0], ",")
				fmt.Fprintf(&b, `<circle class="dot s-%s" cx="%s" cy="%s" r="2.5"/>`, l.Tone, xy[0], xy[1])
			default:
				fmt.Fprintf(&b, `<polyline class="ln l-%s" points="%s"/>`, l.Tone, strings.Join(seg, " "))
			}
			seg = seg[:0]
		}
		for i, v := range l.Values {
			if math.IsNaN(v) {
				flush()
				continue
			}
			seg = append(seg, fmt.Sprintf("%.2f,%.2f", svgLeft+(float64(i)+0.5)*slot, y(v)))
		}
		flush()
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// gauge is one half-circle gauge tile.
type gauge struct {
	Title, Value, Hint string
	// Frac is the needle position, 0 to 1.
	Frac float64
	Tone string
}

// gaugeSVG draws g's arc.
func gaugeSVG(g gauge) template.HTML {
	f := math.Max(0, math.Min(1, g.Frac))
	const cx, cy, r = 60.0, 58.0, 46.0
	arc := func(to float64) string {
		a := math.Pi * (1 - to)
		x, y := cx+r*math.Cos(a), cy-r*math.Sin(a)
		return fmt.Sprintf("M %.2f %.2f A %.0f %.0f 0 0 1 %.2f %.2f", cx-r, cy, r, r, x, y)
	}
	var b strings.Builder
	b.WriteString(`<svg class="gauge" viewBox="0 0 120 66" aria-hidden="true">`)
	fmt.Fprintf(&b, `<path class="track" d="%s"/>`, arc(1))
	if f > 0 {
		fmt.Fprintf(&b, `<path class="val l-%s" d="%s"/>`, g.Tone, arc(math.Max(f, 0.005)))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// slice is one donut segment.
type slice struct {
	Key   string
	Count int
	Pct   float64
	Tone  string
}

// donutSVG draws the slices as a ring; stroke-dasharray on a circle of
// circumference 100 makes each segment's length its percentage.
func donutSVG(title string, slices []slice) template.HTML {
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="donut" viewBox="0 0 42 42" role="img" aria-label="%s">`, html.EscapeString(title))
	b.WriteString(`<circle class="track" cx="21" cy="21" r="15.915"/>`)
	offset := 25.0 // start at 12 o'clock
	for _, s := range slices {
		if s.Pct <= 0 {
			continue
		}
		fmt.Fprintf(&b, `<circle class="seg l-%s" cx="21" cy="21" r="15.915" stroke-dasharray="%.3f %.3f" stroke-dashoffset="%.3f"><title>%s: %s (%.1f%%)</title></circle>`,
			s.Tone, s.Pct, 100-s.Pct, offset, html.EscapeString(s.Key), groupDigits(s.Count), s.Pct)
		offset -= s.Pct
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}
