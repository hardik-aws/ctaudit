package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/query"
	"github.com/gsmappdev/ctaudit/internal/s3src"
)

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// objectWith builds a one-record CloudTrail object.
func objectWith(t *testing.T, eventName, actor, errCode, hour string) []byte {
	t.Helper()
	body := fmt.Sprintf(`{"Records":[{
		"eventTime":"2026-09-20T%s:00:00Z",
		"eventSource":"s3.amazonaws.com",
		"eventName":%q,
		"awsRegion":"us-east-1",
		"sourceIPAddress":"203.0.113.44",
		"eventID":"id-%s-%s",
		"errorCode":%q,
		"readOnly":false,
		"recipientAccountId":"111122223333",
		"userIdentity":{"type":"IAMUser","arn":%q}
	}]}`, hour, eventName, eventName, hour, errCode, actor)
	return gz(t, body)
}

func testScope() s3src.Scope {
	day := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	return s3src.Scope{
		Accounts: []string{"111122223333"},
		Regions:  []string{"us-east-1"},
		Start:    day,
		End:      day,
	}
}

const testPrefix = "AWSLogs/111122223333/CloudTrail/us-east-1/2026/09/20/"

func key(name string) string {
	return testPrefix + "111122223333_CloudTrail_us-east-1_20260920T0000Z_" + name + ".json.gz"
}

func TestRunAggregatesAcrossObjects(t *testing.T) {
	store := s3src.NewMemStore(map[string][]byte{
		key("a"): objectWith(t, "DeleteBucket", "arn:aws:iam::1:user/alice", "", "14"),
		key("b"): objectWith(t, "PutObject", "arn:aws:iam::1:user/bob", "", "15"),
		key("c"): objectWith(t, "GetObject", "arn:aws:iam::1:user/bob", "AccessDenied", "16"),
	})

	res, err := Run(context.Background(), store, Options{Scope: testScope()})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if res.ObjectsScanned != 3 {
		t.Errorf("ObjectsScanned = %d, want 3", res.ObjectsScanned)
	}
	if res.RecordsRead != 3 {
		t.Errorf("RecordsRead = %d, want 3", res.RecordsRead)
	}
	if res.MatchedRecords != 3 {
		t.Errorf("MatchedRecords = %d, want 3", res.MatchedRecords)
	}
	if res.Summary.TotalEvents != 3 {
		t.Errorf("Summary.TotalEvents = %d, want 3", res.Summary.TotalEvents)
	}
	if res.Summary.ByPrincipal["arn:aws:iam::1:user/bob"] != 2 {
		t.Errorf("ByPrincipal[bob] = %d, want 2", res.Summary.ByPrincipal["arn:aws:iam::1:user/bob"])
	}
	if res.Summary.ErrorEvents != 1 {
		t.Errorf("ErrorEvents = %d, want 1", res.Summary.ErrorEvents)
	}
	if len(res.Errors) != 0 {
		t.Errorf("Errors = %v, want none", res.Errors)
	}
}

func TestRunSkipsDigestAndNonLogKeys(t *testing.T) {
	store := s3src.NewMemStore(map[string][]byte{
		key("a"): objectWith(t, "DeleteBucket", "arn:aws:iam::1:user/alice", "", "14"),
		testPrefix + "111122223333_CloudTrail-Digest_us-east-1_x.json.gz": gz(t, `{"Records":[]}`),
		testPrefix + "README.md": []byte("not a log"),
	})

	res, err := Run(context.Background(), store, Options{Scope: testScope()})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ObjectsScanned != 1 {
		t.Errorf("ObjectsScanned = %d, want 1 (digest and non-log keys must be skipped)", res.ObjectsScanned)
	}
}

func TestRunAppliesFilterAndCollectsMatches(t *testing.T) {
	store := s3src.NewMemStore(map[string][]byte{
		key("a"): objectWith(t, "DeleteBucket", "arn:aws:iam::1:user/alice", "", "14"),
		key("b"): objectWith(t, "PutObject", "arn:aws:iam::1:user/bob", "", "15"),
	})

	res, err := Run(context.Background(), store, Options{
		Scope:     testScope(),
		Filter:    query.Filter{Principal: "alice"},
		MaxEvents: 10,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if res.RecordsRead != 2 {
		t.Errorf("RecordsRead = %d, want 2 (both objects are still read)", res.RecordsRead)
	}
	if res.MatchedRecords != 1 {
		t.Errorf("MatchedRecords = %d, want 1", res.MatchedRecords)
	}
	if res.Summary.TotalEvents != 1 {
		t.Errorf("Summary.TotalEvents = %d, want 1 (stats cover matched records only)", res.Summary.TotalEvents)
	}
	if len(res.Matches) != 1 || res.Matches[0].EventName != "DeleteBucket" {
		t.Fatalf("Matches = %+v, want the single DeleteBucket record", res.Matches)
	}
}

func TestRunSortsMatchesByTime(t *testing.T) {
	store := s3src.NewMemStore(map[string][]byte{
		key("late"):  objectWith(t, "DeleteBucket", "arn:aws:iam::1:user/alice", "", "18"),
		key("early"): objectWith(t, "PutBucketAcl", "arn:aws:iam::1:user/alice", "", "09"),
	})

	res, err := Run(context.Background(), store, Options{
		Scope:     testScope(),
		Filter:    query.Filter{Principal: "alice"},
		MaxEvents: 10,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(res.Matches))
	}
	if !res.Matches[0].EventTime.Before(res.Matches[1].EventTime) {
		t.Error("Matches must be sorted by event time ascending")
	}
}

func TestRunHonoursMaxEvents(t *testing.T) {
	objects := map[string][]byte{}
	for i := 0; i < 20; i++ {
		objects[key(fmt.Sprintf("o%02d", i))] = objectWith(t, "DeleteBucket", "arn:aws:iam::1:user/alice", "", "14")
	}
	store := s3src.NewMemStore(objects)

	res, err := Run(context.Background(), store, Options{
		Scope:        testScope(),
		Filter:       query.Filter{Principal: "alice"},
		MaxEvents:    5,
		FetchWorkers: 1,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Matches) > 5 {
		t.Errorf("got %d matches, want at most MaxEvents=5", len(res.Matches))
	}
	if res.MatchedRecords != 20 {
		t.Errorf("MatchedRecords = %d, want 20 (the cap limits retention, not counting)", res.MatchedRecords)
	}
}

func TestRunProducesFindings(t *testing.T) {
	body := gz(t, `{"Records":[{
		"eventTime":"2026-09-20T02:00:00Z",
		"eventSource":"cloudtrail.amazonaws.com",
		"eventName":"StopLogging",
		"awsRegion":"us-east-1",
		"eventID":"tamper-1",
		"recipientAccountId":"111122223333",
		"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::1:user/alice"}
	}]}`)
	store := s3src.NewMemStore(map[string][]byte{key("t"): body})

	res, err := Run(context.Background(), store, Options{Scope: testScope()})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Rule != "cloudtrail-tamper" {
		t.Errorf("finding rule = %q, want cloudtrail-tamper", res.Findings[0].Rule)
	}
}

func TestRunKeepsCriticalSeverityPastFindingsCap(t *testing.T) {
	objects := map[string][]byte{}
	for i := 0; i < 5; i++ {
		// LOW access-denied findings, sorted (and so processed) before the
		// critical one below.
		objects[key(fmt.Sprintf("low%d", i))] = objectWith(t, "GetObject", "arn:aws:iam::1:user/alice", "AccessDenied", "10")
	}
	objects[key("zzz-critical")] = gz(t, `{"Records":[{
		"eventTime":"2026-09-20T23:00:00Z",
		"eventSource":"cloudtrail.amazonaws.com",
		"eventName":"StopLogging",
		"awsRegion":"us-east-1",
		"eventID":"tamper-cap",
		"recipientAccountId":"111122223333",
		"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::1:user/alice"}
	}]}`)
	store := s3src.NewMemStore(objects)

	res, err := Run(context.Background(), store, Options{
		Scope:        testScope(),
		FindingsCap:  3,
		ListWorkers:  1,
		FetchWorkers: 1,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.DroppedFindings == 0 {
		t.Fatalf("DroppedFindings = 0, want at least one finding dropped past the cap of 3")
	}
	if !res.HasFindings {
		t.Fatalf("HasFindings = false, want true")
	}
	if res.MaxSeverity != findings.SevCritical {
		t.Fatalf("MaxSeverity = %v, want CRITICAL even though the cap discarded some findings", res.MaxSeverity)
	}
	total := 0
	for _, n := range res.SeverityCounts {
		total += n
	}
	if res.SeverityCounts[findings.SevCritical] != 1 || total != len(res.Findings)+res.DroppedFindings {
		t.Errorf("SeverityCounts = %v, want 1 critical and %d hits in total", res.SeverityCounts, len(res.Findings)+res.DroppedFindings)
	}
	found := false
	for _, f := range res.Findings {
		if f.Rule == "cloudtrail-tamper" {
			found = true
		}
	}
	if !found {
		t.Errorf("Findings = %+v, want the CRITICAL cloudtrail-tamper finding retained despite the cap", res.Findings)
	}
}

func TestRunRecordsPerObjectErrorsWithoutFailing(t *testing.T) {
	store := s3src.NewMemStore(map[string][]byte{
		key("good"): objectWith(t, "DeleteBucket", "arn:aws:iam::1:user/alice", "", "14"),
		key("bad"):  []byte("this is not gzip"),
	})

	res, err := Run(context.Background(), store, Options{Scope: testScope()})
	if err != nil {
		t.Fatalf("Run must not fail the whole scan for one bad object: %v", err)
	}
	if res.RecordsRead != 1 {
		t.Errorf("RecordsRead = %d, want 1", res.RecordsRead)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("Errors = %v, want exactly one entry", res.Errors)
	}
}

func TestRunErrorsOnEmptyScope(t *testing.T) {
	store := s3src.NewMemStore(nil)
	if _, err := Run(context.Background(), store, Options{}); err == nil {
		t.Fatal("Run with an empty scope returned nil error")
	}
}

func TestRunRespectsCancelledContext(t *testing.T) {
	store := s3src.NewMemStore(map[string][]byte{
		key("a"): objectWith(t, "DeleteBucket", "arn:aws:iam::1:user/alice", "", "14"),
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Run(ctx, store, Options{Scope: testScope()}); err == nil {
		t.Fatal("Run with a cancelled context returned nil error")
	}
}
