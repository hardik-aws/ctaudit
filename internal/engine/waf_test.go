package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/s3src"
	"github.com/gsmappdev/ctaudit/internal/waflog"
)

const wafTestAccount = "111122223333"

func wafKey(acl, ts string, obj string) string {
	return "AWSLogs/" + wafTestAccount + "/WAFLogs/us-east-1/" + acl + "/2026/09/20/10/00/" + ts + "-" + obj
}

// wafLine builds a minimal JSON WAF log line.
func wafLine(ts int64, acl, action, clientIP string) string {
	return `{"timestamp":` + itoa(ts) + `,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/` + acl + `/abcd",` +
		`"terminatingRuleId":"rule-1","terminatingRuleType":"REGULAR","action":"` + action + `",` +
		`"httpSourceName":"ALB","httpRequest":{"clientIp":"` + clientIP + `","country":"US","headers":[],` +
		`"uri":"/","httpMethod":"GET","requestId":"1"}}`
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func wafScope() s3src.Scope {
	day := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	return s3src.Scope{Accounts: []string{wafTestAccount}, Regions: []string{"us-east-1"}, Start: day, End: day}
}

func TestRunWAFWebACLFilter(t *testing.T) {
	prodTS := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC).UnixMilli()
	store := s3src.NewMemStore(map[string][]byte{
		wafKey("prod-acl", "1", "a.log.gz"): gz(t, wafLine(prodTS, "prod-acl", "ALLOW", "1.1.1.1")+"\n"),
		wafKey("test-acl", "1", "b.log.gz"): gz(t, wafLine(prodTS, "test-acl", "ALLOW", "2.2.2.2")+"\n"),
	})

	res, err := RunWAF(context.Background(), store, WAFOptions{Scope: wafScope(), WebACLs: []string{"prod"}})
	if err != nil {
		t.Fatalf("RunWAF: %v", err)
	}
	if res.ObjectsScanned != 1 {
		t.Errorf("ObjectsScanned = %d, want 1 (only prod object read)", res.ObjectsScanned)
	}
	if len(res.WebACLs) != 1 || res.WebACLs[0] != "prod-acl" {
		t.Errorf("WebACLs = %v, want [prod-acl]", res.WebACLs)
	}
}

func TestRunWAFWindowTrimming(t *testing.T) {
	ts := time.Date(2026, 9, 21, 1, 0, 0, 0, time.UTC).UnixMilli()
	store := s3src.NewMemStore(map[string][]byte{
		wafKey("prod-acl", "1", "a.log.gz"): gz(t, wafLine(ts, "prod-acl", "ALLOW", "1.1.1.1")+"\n"),
	})
	until := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	res, err := RunWAF(context.Background(), store, WAFOptions{
		Scope:  wafScope(),
		Filter: waflog.Filter{Until: until},
	})
	if err != nil {
		t.Fatalf("RunWAF: %v", err)
	}
	if res.RecordsRead != 1 {
		t.Errorf("RecordsRead = %d, want 1", res.RecordsRead)
	}
	if res.MatchedRecords != 0 {
		t.Errorf("MatchedRecords = %d, want 0 (record is past Until)", res.MatchedRecords)
	}
}

func TestRunWAFActionFilter(t *testing.T) {
	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC).UnixMilli()
	lines := strings.Join([]string{
		wafLine(base, "prod-acl", "BLOCK", "1.1.1.1"),
		wafLine(base+1000, "prod-acl", "ALLOW", "2.2.2.2"),
		wafLine(base+2000, "prod-acl", "BLOCK", "3.3.3.3"),
	}, "\n") + "\n"
	store := s3src.NewMemStore(map[string][]byte{
		wafKey("prod-acl", "1", "a.log.gz"): gz(t, lines),
	})

	res, err := RunWAF(context.Background(), store, WAFOptions{
		Scope:  wafScope(),
		Filter: waflog.Filter{Actions: []string{"BLOCK"}},
	})
	if err != nil {
		t.Fatalf("RunWAF: %v", err)
	}
	if res.MatchedRecords != 2 {
		t.Errorf("MatchedRecords = %d, want 2", res.MatchedRecords)
	}
	if res.Summary.Total != res.MatchedRecords {
		t.Errorf("Summary.Total = %d, want %d", res.Summary.Total, res.MatchedRecords)
	}
}

func TestRunWAFMaxEventsKeepsEarliest(t *testing.T) {
	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC).UnixMilli()
	objs := map[string][]byte{}
	for i := 0; i < 4; i++ {
		ts := base + int64(i)*1000*3600
		objs[wafKey("prod-acl", itoa(int64(i)), "x.log.gz")] = gz(t, wafLine(ts, "prod-acl", "ALLOW", "1.1.1.1")+"\n")
	}
	store := s3src.NewMemStore(objs)

	res, err := RunWAF(context.Background(), store, WAFOptions{Scope: wafScope(), MaxEvents: 1})
	if err != nil {
		t.Fatalf("RunWAF: %v", err)
	}
	if res.MatchedRecords != 4 {
		t.Errorf("MatchedRecords = %d, want 4 (stats cover all)", res.MatchedRecords)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("Matches = %d, want 1", len(res.Matches))
	}
	if res.Matches[0].Time.UnixMilli() != base {
		t.Errorf("kept match not earliest: %v", res.Matches[0].Time)
	}
}

func TestRunWAFCorruptObject(t *testing.T) {
	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC).UnixMilli()
	store := s3src.NewMemStore(map[string][]byte{
		wafKey("prod-acl", "1", "good.log.gz"): gz(t, wafLine(base, "prod-acl", "ALLOW", "1.1.1.1")+"\n"),
		wafKey("prod-acl", "2", "bad.log.gz"):  []byte("\x1f\x8bxx"),
	})

	res, err := RunWAF(context.Background(), store, WAFOptions{Scope: wafScope()})
	if err != nil {
		t.Fatalf("RunWAF: %v", err)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("Errors = %v, want exactly 1", res.Errors)
	}
	if res.ObjectsScanned != 1 || res.MatchedRecords != 1 {
		t.Errorf("objects=%d matched=%d, want 1/1", res.ObjectsScanned, res.MatchedRecords)
	}
}

func TestRunWAFEmit(t *testing.T) {
	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC).UnixMilli()
	objs := map[string][]byte{}
	for i := 0; i < 3; i++ {
		ts := base + int64(i)*1000*3600
		objs[wafKey("prod-acl", itoa(int64(i)), "x.log.gz")] = gz(t, wafLine(ts, "prod-acl", "ALLOW", "1.1.1.1")+"\n")
	}
	store := s3src.NewMemStore(objs)

	var ec emitCounter
	res, err := RunWAF(context.Background(), store, WAFOptions{
		Scope:     wafScope(),
		MaxEvents: 1,
		Emit: func() func(waflog.Entry) {
			n := ec.new()
			return func(waflog.Entry) { *n++ }
		},
	})
	if err != nil {
		t.Fatalf("RunWAF: %v", err)
	}
	if _, emitted := ec.total(); emitted != 3 {
		t.Errorf("Emit received %d entries, want 3 (uncapped)", emitted)
	}
	if len(res.Matches) != 1 {
		t.Errorf("Matches = %d, want capped to 1", len(res.Matches))
	}
}

func TestRunWAFFindings(t *testing.T) {
	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC).UnixMilli()
	lines := strings.Join([]string{
		wafLine(base, "prod-acl", "BLOCK", "9.9.9.9"),
		wafLine(base+1000, "prod-acl", "BLOCK", "9.9.9.9"),
		wafLine(base+2000, "prod-acl", "BLOCK", "9.9.9.9"),
	}, "\n") + "\n"
	store := s3src.NewMemStore(map[string][]byte{
		wafKey("prod-acl", "1", "a.log.gz"): gz(t, lines),
	})

	res, err := RunWAF(context.Background(), store, WAFOptions{Scope: wafScope(), BlockThreshold: 2})
	if err != nil {
		t.Fatalf("RunWAF: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Error("want at least one finding when a client exceeds BlockThreshold")
	}
}

func TestRunWAFEmptyScope(t *testing.T) {
	_, err := RunWAF(context.Background(), s3src.NewMemStore(nil), WAFOptions{})
	if err == nil || !strings.Contains(err.Error(), "empty scan scope") {
		t.Fatalf("err = %v, want an 'empty scan scope' error", err)
	}
}

func TestRunWAFNoACLFound(t *testing.T) {
	store := s3src.NewMemStore(map[string][]byte{
		"AWSLogs/" + wafTestAccount + "/CloudTrail/us-east-1/2026/09/20/x.json.gz": []byte("out of scope"),
	})
	res, err := RunWAF(context.Background(), store, WAFOptions{Scope: wafScope()})
	if err != nil {
		t.Fatalf("RunWAF: %v", err)
	}
	if res.ObjectsScanned != 0 {
		t.Errorf("ObjectsScanned = %d, want 0", res.ObjectsScanned)
	}
	if len(res.WebACLs) != 0 {
		t.Errorf("WebACLs = %v, want none", res.WebACLs)
	}
}
