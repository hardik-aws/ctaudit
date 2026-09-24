package elblog

import (
	"testing"
	"time"
)

func TestFilterMatch(t *testing.T) {
	t0 := time.Date(2026, 9, 23, 7, 0, 0, 0, time.UTC)
	e := Entry{
		Time: t0, ClientIP: "10.1.2.3", Host: "tiles.example.com", Path: "/data/v3/1/2/3.pbf",
		Target: "10.9.0.5:8080", UserAgent: "Mozilla/5.0 okhttp", Method: "GET",
		ELBStatus: "404", Latency: 0.75,
	}
	cases := []struct {
		name string
		f    Filter
		want bool
	}{
		{"empty", Filter{}, true},
		{"ip", Filter{ClientIP: "10.1."}, true},
		{"ip miss", Filter{ClientIP: "192."}, false},
		{"host fold", Filter{Host: "TILES"}, true},
		{"path", Filter{Path: "/data/v3"}, true},
		{"path miss", Filter{Path: "/styles"}, false},
		{"target", Filter{Target: ":8080"}, true},
		{"ua", Filter{UserAgent: "OKHTTP"}, true},
		{"method", Filter{Methods: []string{"post", "get"}}, true},
		{"method miss", Filter{Methods: []string{"POST"}}, false},
		{"status class", Filter{Statuses: []string{"4xx"}}, true},
		{"status class upper", Filter{Statuses: []string{"4XX"}}, true},
		{"status bare digit", Filter{Statuses: []string{"4"}}, true},
		{"status exact", Filter{Statuses: []string{"404"}}, true},
		{"status exact miss", Filter{Statuses: []string{"403"}}, false},
		{"status class miss", Filter{Statuses: []string{"5xx"}}, false},
		{"slower", Filter{SlowerThan: 500 * time.Millisecond}, true},
		{"not slower", Filter{SlowerThan: time.Second}, false},
		{"since", Filter{Since: t0}, true},
		{"since miss", Filter{Since: t0.Add(time.Second)}, false},
		{"until exclusive", Filter{Until: t0}, false},
		{"until", Filter{Until: t0.Add(time.Second)}, true},
	}
	for _, c := range cases {
		if got := c.f.Match(e); got != c.want {
			t.Errorf("%s: Match = %v, want %v", c.name, got, c.want)
		}
	}

	unknown := e
	unknown.Latency = -1
	if (Filter{SlowerThan: time.Millisecond}).Match(unknown) {
		t.Error("unknown latency must not match SlowerThan")
	}
	sni := Entry{DomainName: "api.example.com"}
	if !(Filter{Host: "api."}).Match(sni) {
		t.Error("host filter should fall back to SNI")
	}
}

func TestFilterIsNarrowing(t *testing.T) {
	if (Filter{Since: time.Now(), Until: time.Now()}).IsNarrowing() {
		t.Error("time bounds alone are not narrowing")
	}
	for _, f := range []Filter{
		{ClientIP: "1"}, {Host: "h"}, {Path: "p"}, {Target: "t"}, {UserAgent: "u"},
		{Methods: []string{"GET"}}, {Statuses: []string{"5xx"}}, {SlowerThan: time.Second},
	} {
		if !f.IsNarrowing() {
			t.Errorf("%+v should be narrowing", f)
		}
	}
}

func TestFilterMatchConn(t *testing.T) {
	e := Entry{Conn: true, ClientIP: "49.36.71.40", Time: time.Date(2026, 9, 23, 7, 0, 0, 0, time.UTC)}
	if !(Filter{}).MatchConn(e) || !(Filter{ClientIP: "49.36"}).MatchConn(e) {
		t.Error("expected match")
	}
	if (Filter{ClientIP: "10."}).MatchConn(e) || (Filter{Host: "x"}).MatchConn(e) ||
		(Filter{Until: e.Time}).MatchConn(e) {
		t.Error("expected no match")
	}
}
