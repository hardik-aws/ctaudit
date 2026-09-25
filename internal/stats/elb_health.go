package stats

import (
	"sort"
	"strings"

	"github.com/gsmappdev/ctaudit/internal/elblog"
)

// statusClass maps a status code to its class digit, 1 to 5, or 0 when the
// code is missing or not an HTTP status.
func statusClass(code string) int {
	if len(code) != 3 || code[0] < '1' || code[0] > '5' {
		return 0
	}
	return int(code[0] - '0')
}

// LatStat is the count, sum, minimum, and maximum of a set of durations in
// seconds. Only measurable (>= 0) values are added.
type LatStat struct {
	Count int
	Sum   float64
	Min   float64
	Max   float64
}

func (l *LatStat) add(v float64) {
	if v < 0 {
		return
	}
	if l.Count == 0 || v < l.Min {
		l.Min = v
	}
	if v > l.Max {
		l.Max = v
	}
	l.Count++
	l.Sum += v
}

func (l *LatStat) merge(o LatStat) {
	if o.Count == 0 {
		return
	}
	if l.Count == 0 || o.Min < l.Min {
		l.Min = o.Min
	}
	if o.Max > l.Max {
		l.Max = o.Max
	}
	l.Count += o.Count
	l.Sum += o.Sum
}

// Avg returns the mean, or -1 when nothing was measured.
func (l LatStat) Avg() float64 {
	if l.Count == 0 {
		return -1
	}
	return l.Sum / float64(l.Count)
}

// TimeBucket aggregates the requests of one minute. ELB and Target are
// indexed by status class: 1 to 5 for 1xx to 5xx, and 0 for a missing
// status (for Target, no target response).
type TimeBucket struct {
	Requests   int
	ELB        [6]int
	Target     [6]int
	ConnErrors int
	TargetTime LatStat
	Latency    LatStat
}

func (b *TimeBucket) add(e elblog.Entry) {
	b.Requests++
	b.ELB[statusClass(e.ELBStatus)]++
	b.Target[statusClass(e.TargetStatus)]++
	if e.TargetConnError() {
		b.ConnErrors++
	}
	b.TargetTime.add(e.TargetTime)
	b.Latency.add(e.Latency)
}

// Merge folds o into b.
func (b *TimeBucket) Merge(o *TimeBucket) {
	b.Requests += o.Requests
	for i := range b.ELB {
		b.ELB[i] += o.ELB[i]
		b.Target[i] += o.Target[i]
	}
	b.ConnErrors += o.ConnErrors
	b.TargetTime.merge(o.TargetTime)
	b.Latency.merge(o.Latency)
}

// GroupStats aggregates the requests routed to one target group.
type GroupStats struct {
	Requests   int
	Target     [6]int // by target status class, as in TimeBucket
	ELB5xx     int
	ConnErrors int
	TargetTime LatStat
	Targets    Counter
}

func (g *GroupStats) add(e elblog.Entry) {
	g.Requests++
	g.Target[statusClass(e.TargetStatus)]++
	if statusClass(e.ELBStatus) == 5 {
		g.ELB5xx++
	}
	if e.TargetConnError() {
		g.ConnErrors++
	}
	g.TargetTime.add(e.TargetTime)
	g.Targets.add(e.Target)
}

func (g *GroupStats) merge(o *GroupStats) {
	g.Requests += o.Requests
	for i := range g.Target {
		g.Target[i] += o.Target[i]
	}
	g.ELB5xx += o.ELB5xx
	g.ConnErrors += o.ConnErrors
	g.TargetTime.merge(o.TargetTime)
	g.Targets.merge(o.Targets)
}

// GroupName shortens a target group ARN to "name/id", or returns it as is.
func GroupName(arn string) string {
	if _, rest, ok := strings.Cut(arn, ":targetgroup/"); ok {
		return rest
	}
	return arn
}

// NamedGroup is one row of the target group table.
type NamedGroup struct {
	ARN string
	*GroupStats
}

// TopGroups returns up to n target groups, busiest first.
func (s *ELBSummary) TopGroups(n int) []NamedGroup {
	out := make([]NamedGroup, 0, len(s.ByTargetGroup))
	for k, g := range s.ByTargetGroup {
		out = append(out, NamedGroup{k, g})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].ARN < out[j].ARN
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// PathLatency is one row of the slowest paths table.
type PathLatency struct {
	Path string
	LatStat
}

// SlowestPaths returns up to n normalized paths ordered by average latency,
// slowest first. Paths with no measurable latency are left out.
func (s *ELBSummary) SlowestPaths(n int) []PathLatency {
	out := make([]PathLatency, 0, len(s.PathTiming))
	for k, l := range s.PathTiming {
		if l.Count > 0 {
			out = append(out, PathLatency{k, *l})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i].Avg(), out[j].Avg()
		if ai != aj {
			return ai > aj
		}
		return out[i].Path < out[j].Path
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Targets5xxShare returns how many distinct targets answered with a 5xx and
// how many distinct targets were seen.
func (s *ELBSummary) Targets5xxShare() (bad, seen int) {
	return len(s.ByTarget5xx), len(s.ByTarget)
}

// AvgTargetTime returns the mean target response time in seconds, or -1.
func (s *ELBSummary) AvgTargetTime() float64 { return s.TargetTime.Avg() }

// addHealth folds the health and timeline aggregates of one entry.
func (s *ELBSummary) addHealth(e elblog.Entry, path string) {
	s.TargetTime.add(e.TargetTime)
	if e.TargetConnError() {
		s.TargetConnErrors++
	}
	if statusClass(e.TargetStatus) == 5 {
		s.ByTarget5xx.add(e.Target)
	}
	if !e.Time.IsZero() {
		m := e.Time.Unix() / 60
		b := s.Timeline[m]
		if b == nil {
			b = &TimeBucket{}
			s.Timeline[m] = b
		}
		b.add(e)
	}
	if e.TargetGroupARN != "" {
		g := s.ByTargetGroup[e.TargetGroupARN]
		if g == nil {
			g = &GroupStats{Targets: Counter{}}
			s.ByTargetGroup[e.TargetGroupARN] = g
		}
		g.add(e)
	}
	if path != "" && e.Latency >= 0 {
		l := s.PathTiming[path]
		if l == nil {
			l = &LatStat{}
			s.PathTiming[path] = l
		}
		l.add(e.Latency)
	}
}

func (s *ELBSummary) mergeHealth(o *ELBSummary) {
	s.TargetTime.merge(o.TargetTime)
	s.TargetConnErrors += o.TargetConnErrors
	s.ByTarget5xx.merge(o.ByTarget5xx)
	for m, b := range o.Timeline {
		if cur := s.Timeline[m]; cur != nil {
			cur.Merge(b)
		} else {
			c := *b
			s.Timeline[m] = &c
		}
	}
	for k, g := range o.ByTargetGroup {
		cur := s.ByTargetGroup[k]
		if cur == nil {
			cur = &GroupStats{Targets: Counter{}}
			s.ByTargetGroup[k] = cur
		}
		cur.merge(g)
	}
	for k, l := range o.PathTiming {
		cur := s.PathTiming[k]
		if cur == nil {
			cur = &LatStat{}
			s.PathTiming[k] = cur
		}
		cur.merge(*l)
	}
}
