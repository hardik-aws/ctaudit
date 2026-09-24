package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/s3src"
)

const elbTestPrefix = "AWSLogs/702656214742/elasticloadbalancing/us-east-1/2026/09/23/"

func elbKey(seg, suffix string) string {
	return elbTestPrefix + "702656214742_elasticloadbalancing_us-east-1_" + seg + "_20260923T0715Z_100.51.96.60_" + suffix
}

// albLine builds a minimal but complete ALB log line.
func albLine(ts, client, status, path string, latency float64) string {
	return fmt.Sprintf(`https %s app/tiles/98e3 %s:5815 10.20.20.37:80 0.001 %.3f 0.000 %s %s 153 3860 "GET https://tiles.example.com:443%s HTTP/1.1" "Dart/3.11" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:tg "Root=1" "tiles.example.com" "arn:cert" 2 %s "forward" "-" "-" "10.20.20.37:80" "200" "-" "-" TID_x "-" "-" "-"`,
		ts, client, latency, status, status, path, ts)
}

func elbScope() s3src.Scope {
	day := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	return s3src.Scope{Accounts: []string{"702656214742"}, Regions: []string{"us-east-1"}, Start: day, End: day}
}

func TestRunELBAggregatesAndFilters(t *testing.T) {
	a := strings.Join([]string{
		albLine("2026-09-23T07:15:47.000000Z", "1.1.1.1", "200", "/data/1/2/3.pbf", 0.003),
		albLine("2026-09-23T07:10:00.000000Z", "2.2.2.2", "404", "/missing", 0.001),
	}, "\n") + "\n"
	b := albLine("2026-09-23T08:00:00.000000Z", "2.2.2.2", "502", "/data/4/5/6.pbf", 1.5) + "\nnot a log line\n"
	store := s3src.NewMemStore(map[string][]byte{
		elbKey("app.tiles.98e3", "a.log.gz"):        gz(t, a),
		elbKey("app.tiles.98e3", "b.log.gz"):        gz(t, b),
		elbKey("app.other-lb.1234", "c.log.gz"):     gz(t, albLine("2026-09-23T09:00:00.000000Z", "3.3.3.3", "200", "/", 0.001)),
		elbTestPrefix + "ELBAccessLogTestFile":      []byte("ignored"),
		"AWSLogs/702656214742/CloudTrail/x.json.gz": []byte("out of scope"),
	})

	res, err := RunELB(context.Background(), store, ELBOptions{Scope: elbScope()})
	if err != nil {
		t.Fatalf("RunELB: %v", err)
	}
	if res.ObjectsScanned != 3 || res.RecordsRead != 4 || res.MatchedRecords != 4 {
		t.Errorf("objects/read/matched = %d/%d/%d, want 3/4/4", res.ObjectsScanned, res.RecordsRead, res.MatchedRecords)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "b.log.gz") {
		t.Errorf("Errors = %v, want one error naming b.log.gz", res.Errors)
	}
	s := res.Summary
	if s.Errors4xx != 1 || s.Errors5xx != 1 || s.ByClientIP["2.2.2.2"] != 2 {
		t.Errorf("summary 4xx=%d 5xx=%d ips=%v", s.Errors4xx, s.Errors5xx, s.ByClientIP)
	}
	if s.ByPath["/data/{n}/{n}/{n}.pbf"] != 2 {
		t.Errorf("paths = %v", s.ByPath)
	}
	for i := 1; i < len(res.Matches); i++ {
		if res.Matches[i].Time.Before(res.Matches[i-1].Time) {
			t.Fatal("matches not sorted by time")
		}
	}

	// Filter, LB name, and kind restrictions.
	res, err = RunELB(context.Background(), store, ELBOptions{
		Scope:  elbScope(),
		Filter: elblog.Filter{Statuses: []string{"5xx"}},
		LBs:    []string{"TILES"},
		Kinds:  []elblog.Kind{elblog.ALB},
	})
	if err != nil {
		t.Fatalf("RunELB filtered: %v", err)
	}
	if res.ObjectsScanned != 2 || res.MatchedRecords != 1 || len(res.Matches) != 1 || res.Matches[0].ELBStatus != "502" {
		t.Errorf("filtered: objects=%d matched=%d matches=%+v", res.ObjectsScanned, res.MatchedRecords, res.Matches)
	}

	res, err = RunELB(context.Background(), store, ELBOptions{Scope: elbScope(), Kinds: []elblog.Kind{elblog.NLB}})
	if err != nil {
		t.Fatalf("RunELB nlb: %v", err)
	}
	if res.ObjectsScanned != 0 {
		t.Errorf("NLB-only scan fetched %d ALB objects", res.ObjectsScanned)
	}
}

func TestRunELBMaxEventsKeepsEarliest(t *testing.T) {
	objs := map[string][]byte{}
	for i := 0; i < 6; i++ {
		ts := fmt.Sprintf("2026-09-23T%02d:00:00.000000Z", 10-i)
		objs[elbKey("app.tiles.98e3", fmt.Sprintf("%d.log.gz", i))] = gz(t, albLine(ts, "1.1.1.1", "200", "/", 0.001))
	}
	res, err := RunELB(context.Background(), s3src.NewMemStore(objs), ELBOptions{Scope: elbScope(), MaxEvents: 2, FetchWorkers: 3})
	if err != nil {
		t.Fatalf("RunELB: %v", err)
	}
	if res.MatchedRecords != 6 || len(res.Matches) != 2 {
		t.Fatalf("matched=%d kept=%d", res.MatchedRecords, len(res.Matches))
	}
	if res.Matches[0].Time.Hour() != 5 || res.Matches[1].Time.Hour() != 6 {
		t.Errorf("kept hours %d,%d, want 5,6", res.Matches[0].Time.Hour(), res.Matches[1].Time.Hour())
	}
}

func TestRunELBEmptyScope(t *testing.T) {
	if _, err := RunELB(context.Background(), s3src.NewMemStore(nil), ELBOptions{}); err == nil {
		t.Error("want error for empty scope")
	}
}

func TestRunELBConnectionLogs(t *testing.T) {
	const lb = "app/k8s-tileserver-617dd1df30/98e3a879de9d6b42 3.228.177.57"
	conns := strings.Join([]string{
		`2026-09-23T07:11:27.691358Z 49.36.71.40 64326 443 TLSv1.2 ECDHE-ECDSA-AES128-GCM-SHA256 0.337 "-" - - Success TID_1 secp256r1 ` + lb,
		`2026-09-23T07:11:32.882572Z 147.185.132.159 61814 80 - - - "-" - - - TID_2 - ` + lb,
		`2026-09-23T07:12:01.000000Z 198.51.100.7 50000 443 - - - "-" - - - TID_3 - ` + lb,
	}, "\n") + "\n"
	connKey := elbTestPrefix + "conn_log_702656214742_elasticloadbalancing_us-east-1_app.k8s-tileserver-617dd1df30.98e3a879de9d6b42_20260923T0715Z_54.81.166.60_57hw2gm1.log.gz"
	store := s3src.NewMemStore(map[string][]byte{
		connKey:                              gz(t, conns),
		elbKey("app.tiles.98e3", "a.log.gz"): gz(t, albLine("2026-09-23T07:15:47.000000Z", "49.36.71.40", "200", "/", 0.003)),
	})

	res, err := RunELB(context.Background(), store, ELBOptions{Scope: elbScope()})
	if err != nil {
		t.Fatalf("RunELB: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("Errors = %v", res.Errors)
	}
	if res.ObjectsScanned != 2 || res.RecordsRead != 1 || res.MatchedRecords != 1 || res.Summary.Total != 1 {
		t.Errorf("requests: objects=%d read=%d matched=%d total=%d", res.ObjectsScanned, res.RecordsRead, res.MatchedRecords, res.Summary.Total)
	}
	if res.ConnsRead != 3 || res.MatchedConns != 3 || res.Conns.Total != 3 || res.Conns.HandshakeFailed != 1 || len(res.ConnMatches) != 3 {
		t.Errorf("conns: read=%d matched=%d total=%d failed=%d kept=%d",
			res.ConnsRead, res.MatchedConns, res.Conns.Total, res.Conns.HandshakeFailed, len(res.ConnMatches))
	}

	// Client IP applies to connections; request-only criteria exclude them.
	res, _ = RunELB(context.Background(), store, ELBOptions{Scope: elbScope(), Filter: elblog.Filter{ClientIP: "49.36."}})
	if res.MatchedConns != 1 || res.MatchedRecords != 1 {
		t.Errorf("client filter: conns=%d requests=%d", res.MatchedConns, res.MatchedRecords)
	}
	res, _ = RunELB(context.Background(), store, ELBOptions{Scope: elbScope(), Filter: elblog.Filter{Statuses: []string{"200"}}})
	if res.MatchedConns != 0 || res.ConnsRead != 3 {
		t.Errorf("status filter: conns matched=%d read=%d", res.MatchedConns, res.ConnsRead)
	}
}
