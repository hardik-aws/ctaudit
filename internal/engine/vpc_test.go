package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/flowlog"
	"github.com/gsmappdev/ctaudit/internal/s3src"
	"github.com/gsmappdev/ctaudit/internal/vpcrules"
)

const (
	vpcAcct   = "111122223333"
	vpcHeader = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n"
)

func vpcKey(day, name string) string {
	return "AWSLogs/" + vpcAcct + "/vpcflowlogs/us-east-1/2026/09/" + day + "/" + vpcAcct +
		"_vpcflowlogs_us-east-1_fl-0123456789abcdef0_202609" + day + "T1000Z_" + name + ".log.gz"
}

// vpcRow builds one default-format record starting at ts (Unix seconds).
func vpcRow(ts int64, src, dst string, sport, dport int, action string, bytes int64) string {
	return "2 " + vpcAcct + " eni-0a1b2c3d4e5f60718 " + src + " " + dst + " " + itoa(int64(sport)) + " " + itoa(int64(dport)) +
		" 6 1 " + itoa(bytes) + " " + itoa(ts) + " " + itoa(ts+60) + " " + action + " OK\n"
}

func vpcScope() (s3src.Scope, flowlog.Filter) {
	day := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	return s3src.Scope{Accounts: []string{vpcAcct}, Regions: []string{"us-east-1"}, Start: day, End: day.AddDate(0, 0, 1)},
		flowlog.Filter{Since: day, Until: day.AddDate(0, 0, 1)}
}

const (
	ts10      = 1789898400 // 2026-09-20 10:00 UTC
	ts11      = 1789902000 // 2026-09-20 11:00 UTC
	tsNextDay = 1789952400 // 2026-09-21 01:00 UTC, outside the window
)

func TestRunVPCAggregates(t *testing.T) {
	obj := vpcHeader +
		vpcRow(ts10, "203.0.113.9", "10.0.1.10", 40001, 22, "REJECT", 40) +
		vpcRow(ts11, "198.51.100.7", "10.0.1.10", 51544, 443, "ACCEPT", 5120) +
		vpcRow(tsNextDay, "198.51.100.7", "10.0.1.10", 51544, 443, "ACCEPT", 999) +
		"2 " + vpcAcct + " eni-0e5f6071829304152 - - - - - - - " + itoa(ts10) + " " + itoa(ts10+60) + " - NODATA\n" +
		"2 " + vpcAcct + " eni-0f60718293041526a - - - - - - - " + itoa(ts10) + " " + itoa(ts10+60) + " - SKIPDATA\n" +
		"2 " + vpcAcct + " eni-0f60718293041526a - - - - - - - " + itoa(tsNextDay) + " " + itoa(tsNextDay+60) + " - NODATA\n"
	store := s3src.NewMemStore(map[string][]byte{
		vpcKey("20", "a"): gz(t, obj),
		// The next day's prefix is also listed because objects are filed
		// under their delivery day.
		vpcKey("21", "b"): gz(t, vpcHeader+vpcRow(ts11+3600, "203.0.113.9", "10.0.1.11", 40002, 23, "REJECT", 40)),
		"AWSLogs/" + vpcAcct + "/vpcflowlogs/us-east-1/2026/09/20/readme.txt": []byte("not a log"),
	})
	scope, filter := vpcScope()
	res, err := RunVPC(context.Background(), store, VPCOptions{Scope: scope, Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	s := res.Summary
	if res.ObjectsScanned != 2 || res.RecordsRead != 7 || len(res.Errors) != 0 {
		t.Fatalf("objects %d records %d errors %v", res.ObjectsScanned, res.RecordsRead, res.Errors)
	}
	if s.Flows != 3 || s.Rejected() != 2 || s.Bytes != 5200 || s.NoData != 1 || s.SkipData != 1 {
		t.Fatalf("summary flows %d rejected %d bytes %d nodata %d skipdata %d", s.Flows, s.Rejected(), s.Bytes, s.NoData, s.SkipData)
	}
	if res.MatchedRecords != 3 || len(res.Matches) != 3 || !res.Matches[0].Start.Equal(time.Unix(ts10, 0)) {
		t.Fatalf("matches %d/%d first %v", res.MatchedRecords, len(res.Matches), res.Matches)
	}
	if len(res.ReadKeys) != 2 {
		t.Fatalf("read keys %v", res.ReadKeys)
	}

	filter.Actions = []string{"REJECT"}
	res, err = RunVPC(context.Background(), store, VPCOptions{Scope: scope, Filter: filter})
	if err != nil || res.MatchedRecords != 2 || res.Summary.Flows != 2 || res.Summary.NoData != 1 {
		t.Fatalf("filtered: matched %d flows %d nodata %d err %v", res.MatchedRecords, res.Summary.Flows, res.Summary.NoData, err)
	}
}

func TestRunVPCMaxEventsAndEmit(t *testing.T) {
	var obj strings.Builder
	obj.WriteString(vpcHeader)
	for i := range 5 {
		obj.WriteString(vpcRow(ts10+int64(i), "203.0.113.9", "10.0.1.10", 40000+i, 22, "REJECT", 40))
	}
	store := s3src.NewMemStore(map[string][]byte{vpcKey("20", "a"): gz(t, obj.String())})
	scope, filter := vpcScope()
	var mu sync.Mutex
	emitted := 0
	res, err := RunVPC(context.Background(), store, VPCOptions{
		Scope: scope, Filter: filter, MaxEvents: 2,
		Emit: func() func(flowlog.Entry) {
			return func(flowlog.Entry) { mu.Lock(); emitted++; mu.Unlock() }
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 2 || res.MatchedRecords != 5 || emitted != 5 || res.Matches[0].SrcPort != 40000 {
		t.Fatalf("matches %d matched %d emitted %d", len(res.Matches), res.MatchedRecords, emitted)
	}
}

func TestRunVPCObjectErrors(t *testing.T) {
	parquet := strings.Replace(vpcKey("20", "p"), ".log.gz", ".parquet", 1)
	store := s3src.NewMemStore(map[string][]byte{
		vpcKey("20", "good"):    gz(t, vpcHeader+vpcRow(ts10, "203.0.113.9", "10.0.1.10", 40001, 22, "REJECT", 40)),
		vpcKey("20", "corrupt"): []byte("\x1f\x8bxx"),
		parquet:                 []byte("PAR1"),
	})
	scope, filter := vpcScope()
	res, err := RunVPC(context.Background(), store, VPCOptions{Scope: scope, Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(res.Errors, "\n")
	if len(res.Errors) != 2 || !strings.Contains(joined, "parquet flow log files are not supported") || res.Summary.Flows != 1 {
		t.Fatalf("errors %v flows %d", res.Errors, res.Summary.Flows)
	}
}

func TestRunVPCHiveLayout(t *testing.T) {
	scope, filter := vpcScope()
	hive := scope.VPCHivePrefix(vpcAcct, "us-east-1") + "year=2026/month=09/day=20/hour=10/" + vpcAcct + "_vpcflowlogs_us-east-1_fl-1_20260920T1000Z_x.log.gz"
	store := s3src.NewMemStore(map[string][]byte{hive: gz(t, vpcHeader)})
	_, err := RunVPC(context.Background(), store, VPCOptions{Scope: scope, Filter: filter})
	if !errors.Is(err, ErrHiveLayout) {
		t.Fatalf("err = %v, want ErrHiveLayout", err)
	}
	// Nothing anywhere: an empty result, not an error.
	res, err := RunVPC(context.Background(), s3src.NewMemStore(nil), VPCOptions{Scope: scope, Filter: filter})
	if err != nil || res.ObjectsScanned != 0 {
		t.Fatalf("empty bucket: %v %+v", err, res)
	}
}

// TestRunVPCIdleTickSkipsHiveProbe is the controller ruling: in serve mode, a
// tick where every flow-log key was already seen (Skip returns true for all
// of them) has ObjectsScanned == 0 just like a truly empty scope, but there
// are real flow log objects in scope. RunVPC must not mistake that for a
// Hive-layout bucket and must not run the discovery probe, even though a
// Hive-layout object also exists.
func TestRunVPCIdleTickSkipsHiveProbe(t *testing.T) {
	scope, filter := vpcScope()
	hive := scope.VPCHivePrefix(vpcAcct, "us-east-1") + "year=2026/month=09/day=20/hour=10/" + vpcAcct + "_vpcflowlogs_us-east-1_fl-1_20260920T1000Z_x.log.gz"
	store := s3src.NewMemStore(map[string][]byte{
		vpcKey("20", "a"): gz(t, vpcHeader+vpcRow(ts10, "203.0.113.9", "10.0.1.10", 40001, 22, "REJECT", 40)),
		hive:              gz(t, vpcHeader),
	})
	res, err := RunVPC(context.Background(), store, VPCOptions{
		Scope: scope, Filter: filter,
		Skip: func(string) bool { return true },
	})
	if err != nil {
		t.Fatalf("idle tick returned an error: %v", err)
	}
	if errors.Is(err, ErrHiveLayout) {
		t.Fatal("idle tick must not trigger the Hive-layout probe")
	}
	if res.ObjectsScanned != 0 {
		t.Fatalf("objects scanned = %d, want 0", res.ObjectsScanned)
	}
}

func TestRunVPCEmptyScope(t *testing.T) {
	if _, err := RunVPC(context.Background(), s3src.NewMemStore(nil), VPCOptions{}); err == nil {
		t.Fatal("empty scope must fail")
	}
}

func TestRunVPCFindings(t *testing.T) {
	var obj strings.Builder
	obj.WriteString(vpcHeader)
	for p := 1; p <= 3; p++ {
		obj.WriteString(vpcRow(ts10, "203.0.113.9", "10.0.1.10", 40000, p, "REJECT", 40))
	}
	store := s3src.NewMemStore(map[string][]byte{vpcKey("20", "a"): gz(t, obj.String())})
	scope, filter := vpcScope()
	res, err := RunVPC(context.Background(), store, VPCOptions{Scope: scope, Filter: filter, Rules: vpcrules.Options{ScanPorts: 3}, FetchWorkers: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Rule != "vpc-port-scan" {
		t.Fatalf("findings %+v", res.Findings)
	}
}
