package stats

import (
	"strconv"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/s3log"
)

func TestS3SummaryAddMerge(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	alice := "arn:aws:iam::111122223333:user/alice"
	a, b := NewS3Summary(), NewS3Summary()
	a.Add(s3log.Entry{Time: t0, Bucket: "data", RemoteIP: "1.1.1.1", Requester: alice, Operation: "REST.GET.OBJECT",
		Key: "k1", Status: 200, BytesSent: 100, TLSVersion: "TLSv1.2", AuthType: "AuthHeader", SigVersion: "SigV4", UserAgent: "cli"})
	a.Add(s3log.Entry{Time: t0.Add(time.Minute), Bucket: "data", RemoteIP: "2.2.2.2", Operation: "REST.PUT.OBJECT",
		Key: "up.php", Status: 200, PlainHTTP: true})
	a.Add(s3log.Entry{Time: t0.Add(2 * time.Minute), Bucket: "data", RemoteIP: "3.3.3.3", Requester: alice,
		Operation: "REST.GET.OBJECT", Key: "secret", Status: 403, ErrorCode: "AccessDenied", BytesSent: 243})
	b.Add(s3log.Entry{Time: t0.Add(-time.Hour), Bucket: "web", RemoteIP: "4.4.4.4", Operation: "REST.GET.OBJECT",
		Key: "index.html", Status: 200, BytesSent: 50})
	b.Add(s3log.Entry{Time: t0.Add(3 * time.Minute), Bucket: "data", RemoteIP: "1.1.1.1", Requester: alice,
		Operation: "BATCH.DELETE.OBJECT", Key: "old", Status: 204})
	b.Add(s3log.Entry{Time: t0.Add(4 * time.Minute), Bucket: "data", RemoteIP: "1.1.1.1", Requester: alice,
		Operation: "REST.PUT.BUCKETPOLICY", Status: 204})
	b.Add(s3log.Entry{Time: t0.Add(5 * time.Minute), Bucket: "data", RemoteIP: "5.5.5.5", Requester: "legacy",
		Operation: "REST.HEAD.OBJECT", Key: "k1", Status: 200, TLSVersion: "TLSv1", SigVersion: "SigV2"})
	a.Merge(b)

	if a.Total != 7 || a.Errors != 1 || a.Denied != 1 || a.Anonymous != 2 || a.BytesSent != 393 {
		t.Fatalf("totals: %+v", a)
	}
	if !a.First.Equal(t0.Add(-time.Hour)) || !a.Last.Equal(t0.Add(5*time.Minute)) {
		t.Fatalf("first/last: %v %v", a.First, a.Last)
	}
	if a.ByOperation["REST.GET.OBJECT"] != 3 || a.ByStatus["200"] != 4 || a.ByErrorCode["AccessDenied"] != 1 || a.ByBucket["data"] != 6 {
		t.Fatalf("counters: %v %v %v %v", a.ByOperation, a.ByStatus, a.ByErrorCode, a.ByBucket)
	}
	if a.ByRequester[s3log.Anonymous] != 2 || a.ByRequester[alice] != 4 || a.ByKey["data/k1"] != 2 || a.ByRemoteIP["1.1.1.1"] != 3 {
		t.Fatalf("open counters: %v %v %v", a.ByRequester, a.ByKey, a.ByRemoteIP)
	}
	if a.ByHour[t0.Unix()/3600]["2xx"] != 5 || a.ByHour[t0.Unix()/3600]["4xx"] != 1 {
		t.Fatalf("ByHour: %v", a.ByHour)
	}
	if a.DeniedByIP["3.3.3.3"] != 1 || a.DeniedByRequester[alice] != 1 || a.DeletesByPrincipal[alice] != 1 {
		t.Fatalf("rule inputs: %v %v %v", a.DeniedByIP, a.DeniedByRequester, a.DeletesByPrincipal)
	}
	if a.BytesByRequester[alice] != 343 || a.BytesByRequester[s3log.Anonymous] != 0 || a.BytesByIP["4.4.4.4"] != 50 {
		t.Fatalf("bytes: %v %v", a.BytesByRequester, a.BytesByIP)
	}
	w := a.AnonWrites["data"]
	if w == nil || w.Count != 1 || w.IPs["2.2.2.2"] != 1 || w.Keys["up.php"] != 1 || w.Ops["REST.PUT.OBJECT"] != 1 {
		t.Fatalf("AnonWrites: %+v", w)
	}
	r := a.AnonReads["web"]
	if r == nil || r.Count != 1 || !r.First.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("AnonReads: %+v", r)
	}
	if len(a.AccessChanges) != 1 || a.AccessChanges[0].Operation != "REST.PUT.BUCKETPOLICY" || a.AccessChanges[0].Principal != alice {
		t.Fatalf("AccessChanges: %+v", a.AccessChanges)
	}
	if a.PlainHTTPBy[s3log.Anonymous] != 1 || a.WeakTLSBy["legacy"] != 1 || a.SigV2By["legacy"] != 1 {
		t.Fatalf("posture: %v %v %v", a.PlainHTTPBy, a.WeakTLSBy, a.SigV2By)
	}
}

func TestS3SummaryCapsOpenCounters(t *testing.T) {
	s := NewS3Summary()
	for i := 0; i < S3MaxKeys+10; i++ {
		s.Add(s3log.Entry{Bucket: "b", Operation: "REST.GET.OBJECT", RemoteIP: "ip-" + strconv.Itoa(i), Status: 200})
	}
	if len(s.ByRemoteIP) != S3MaxKeys+1 || s.ByRemoteIP[S3Other] != 10 {
		t.Fatalf("ByRemoteIP has %d keys, other = %d", len(s.ByRemoteIP), s.ByRemoteIP[S3Other])
	}
	o := NewS3Summary()
	o.Add(s3log.Entry{Bucket: "b", Operation: "REST.GET.OBJECT", RemoteIP: "new-ip", Status: 200})
	s.Merge(o)
	if s.ByRemoteIP["new-ip"] != 0 || s.ByRemoteIP[S3Other] != 11 {
		t.Fatalf("merge past cap: new-ip %d, other %d", s.ByRemoteIP["new-ip"], s.ByRemoteIP[S3Other])
	}
}

func TestS3SummaryAccessChangesKeepEarliest(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	a, b := NewS3Summary(), NewS3Summary()
	for i := 0; i < s3MaxAccessChanges; i++ {
		a.Add(s3log.Entry{Time: t0.Add(time.Duration(i+10) * time.Second), Bucket: "b", Operation: "REST.PUT.ACL", Status: 200})
	}
	b.Add(s3log.Entry{Time: t0, Bucket: "b", Operation: "REST.DELETE.PUBLIC_ACCESS_BLOCK", Status: 204})
	a.Merge(b)
	if len(a.AccessChanges) != s3MaxAccessChanges || a.AccessChanges[0].Operation != "REST.DELETE.PUBLIC_ACCESS_BLOCK" {
		t.Fatalf("kept %d, first %+v", len(a.AccessChanges), a.AccessChanges[0])
	}
}
