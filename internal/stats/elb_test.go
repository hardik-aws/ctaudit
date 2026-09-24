package stats

import (
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
)

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":                            "",
		"/":                           "/",
		"/data/v3/14/2911/6346.pbf":   "/data/v3/{n}/{n}/{n}.pbf",
		"/styles/basic/12/1/2@2x.png": "/styles/basic/{n}/{n}/2@2x.png",
		"/data/roads-z18_v2.json":     "/data/roads-z18_v2.json",
		"/users/42/profile":           "/users/{n}/profile",
		"/.well-known/security.txt":   "/.well-known/security.txt",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestELBSummaryAddMerge(t *testing.T) {
	t0 := time.Date(2026, 9, 23, 7, 0, 0, 0, time.UTC)
	a, b := NewELBSummary(), NewELBSummary()
	a.Add(elblog.Entry{Time: t0, LB: "app/x/1", Type: "https", ELBStatus: "200", Latency: 0.2,
		ReceivedBytes: 10, SentBytes: 100, Host: "tiles.example", Path: "/t/1/2/3.pbf",
		ClientIP: "1.2.3.4", SSLProtocol: "TLSv1.2", SSLCipher: "C1", Actions: "forward", Method: "GET"})
	b.Add(elblog.Entry{Time: t0.Add(2 * time.Hour), LB: "app/x/1", Type: "http", ELBStatus: "404",
		Latency: -1, DomainName: "sni.example", Path: "/t/4/5/6.pbf", ClientIP: "1.2.3.4"})
	b.Add(elblog.Entry{Time: t0.Add(-time.Hour), ELBStatus: "502", Latency: 0.6, ErrorReason: "TargetConnectionError"})
	a.Merge(b)

	if a.Total != 3 || a.Errors4xx != 1 || a.Errors5xx != 1 {
		t.Errorf("total/4xx/5xx = %d %d %d", a.Total, a.Errors4xx, a.Errors5xx)
	}
	if a.LatencyCount != 2 || a.LatencyMax != 0.6 || a.AvgLatency() != 0.4 {
		t.Errorf("latency = %d %v %v", a.LatencyCount, a.LatencyMax, a.AvgLatency())
	}
	if !a.First.Equal(t0.Add(-time.Hour)) || !a.Last.Equal(t0.Add(2*time.Hour)) {
		t.Errorf("first/last = %v %v", a.First, a.Last)
	}
	if a.ByPath["/t/{n}/{n}/{n}.pbf"] != 2 || a.ByClientIP["1.2.3.4"] != 2 {
		t.Errorf("paths = %v ips = %v", a.ByPath, a.ByClientIP)
	}
	if a.ByHost["sni.example"] != 1 || a.ByHost["tiles.example"] != 1 {
		t.Errorf("hosts = %v", a.ByHost)
	}
	if a.ByHour["7"] != 1 || a.ByHour["9"] != 1 || a.ByHour["6"] != 1 {
		t.Errorf("hours = %v", a.ByHour)
	}
	if a.ReceivedBytes != 10 || a.SentBytes != 100 || a.ByErrorReason["TargetConnectionError"] != 1 {
		t.Errorf("bytes/reasons wrong")
	}
	if NewELBSummary().AvgLatency() != 0 {
		t.Error("empty avg should be 0")
	}
	a.Merge(nil)
}
