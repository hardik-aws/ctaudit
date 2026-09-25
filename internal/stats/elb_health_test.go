package stats

import (
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
)

const tgA = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/web/abc"

func TestTargetConnError(t *testing.T) {
	cases := []struct {
		e    elblog.Entry
		want bool
	}{
		{elblog.Entry{ELBStatus: "502", Target: "10.0.0.1:80"}, true},
		{elblog.Entry{ELBStatus: "502", Target: "10.0.0.1:80", TargetStatus: "502"}, false},
		{elblog.Entry{ELBStatus: "503"}, false},
		{elblog.Entry{ELBStatus: "503", ErrorReason: "TargetConnectionErrorCode"}, true},
		{elblog.Entry{ELBStatus: "502", Target: "10.0.0.1:80", Conn: true}, false},
	}
	for i, c := range cases {
		if got := c.e.TargetConnError(); got != c.want {
			t.Errorf("case %d: TargetConnError = %v, want %v", i, got, c.want)
		}
	}
}

func TestELBHealthAddMerge(t *testing.T) {
	t0 := time.Date(2026, 9, 23, 7, 0, 30, 0, time.UTC)
	a, b := NewELBSummary(), NewELBSummary()
	a.Add(elblog.Entry{Time: t0, ELBStatus: "200", TargetStatus: "200", Target: "10.0.0.1:80",
		TargetGroupARN: tgA, TargetTime: 0.2, Latency: 0.25, Path: "/users/1"})
	a.Add(elblog.Entry{Time: t0.Add(10 * time.Second), ELBStatus: "500", TargetStatus: "500",
		Target: "10.0.0.2:80", TargetGroupARN: tgA, TargetTime: 0.6, Latency: 0.7, Path: "/users/2"})
	b.Add(elblog.Entry{Time: t0.Add(2 * time.Minute), ELBStatus: "502", Target: "10.0.0.1:80",
		TargetGroupARN: tgA, TargetTime: -1, Latency: -1, Path: "/health"})
	b.Add(elblog.Entry{Time: t0.Add(2 * time.Minute), ELBStatus: "503", TargetTime: -1, Latency: 0.001})
	a.Merge(b)

	if a.TargetTime.Count != 2 || a.TargetTime.Max != 0.6 || a.TargetTime.Min != 0.2 {
		t.Errorf("target time = %+v", a.TargetTime)
	}
	if got := a.AvgTargetTime(); got < 0.399 || got > 0.401 {
		t.Errorf("avg target time = %v", got)
	}
	if a.TargetConnErrors != 1 {
		t.Errorf("conn errors = %d", a.TargetConnErrors)
	}
	if bad, seen := a.Targets5xxShare(); bad != 1 || seen != 2 {
		t.Errorf("targets 5xx = %d of %d", bad, seen)
	}

	m0 := t0.Unix() / 60
	if len(a.Timeline) != 2 {
		t.Fatalf("timeline minutes = %d", len(a.Timeline))
	}
	first, second := a.Timeline[m0], a.Timeline[m0+2]
	if first == nil || second == nil {
		t.Fatalf("timeline keys = %v", a.Timeline)
	}
	if first.Requests != 2 || first.ELB[2] != 1 || first.ELB[5] != 1 || first.Target[5] != 1 {
		t.Errorf("first bucket = %+v", first)
	}
	if second.Requests != 2 || second.ConnErrors != 1 || second.Target[0] != 2 || second.Latency.Count != 1 {
		t.Errorf("second bucket = %+v", second)
	}

	g := a.ByTargetGroup[tgA]
	if g == nil || g.Requests != 3 || g.ELB5xx != 2 || g.ConnErrors != 1 || len(g.Targets) != 2 {
		t.Fatalf("group = %+v", g)
	}
	if top := a.TopGroups(5); len(top) != 1 || GroupName(top[0].ARN) != "web/abc" {
		t.Errorf("top groups = %+v", top)
	}

	slow := a.SlowestPaths(5)
	if len(slow) != 1 || slow[0].Path != "/users/{n}" || slow[0].Count != 2 || slow[0].Max != 0.7 {
		t.Errorf("slowest paths = %+v", slow)
	}
}

func TestLatStatAvgEmpty(t *testing.T) {
	if got := (LatStat{}).Avg(); got != -1 {
		t.Errorf("empty avg = %v, want -1", got)
	}
}
