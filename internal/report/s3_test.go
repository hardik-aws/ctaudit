package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/s3log"
	"github.com/gsmappdev/ctaudit/internal/s3rules"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

func s3Fixture() (engine.S3Result, Meta) {
	t0 := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	entries := []s3log.Entry{
		{Time: t0, Bucket: "data-bucket", RemoteIP: "192.0.2.44", Operation: "REST.PUT.OBJECT", Key: "x<y>.php",
			Method: "PUT", Path: "/x<y>.php", Status: 200, UserAgent: "<script>alert(1)</script>", PlainHTTP: true, TotalTimeMS: -1, TurnaroundMS: -1},
		{Time: t0.Add(time.Minute), Bucket: "data-bucket", RemoteIP: "192.0.2.50", Requester: "arn:aws:iam::111122223333:user/alice",
			Operation: "REST.GET.OBJECT", Key: "secrets/db.env", Status: 403, ErrorCode: "AccessDenied", BytesSent: 243,
			TLSVersion: "TLSv1.1", SigVersion: "SigV2", AuthType: "AuthHeader", TotalTimeMS: 9, TurnaroundMS: -1},
	}
	sum := stats.NewS3Summary()
	for _, e := range entries {
		sum.Add(e)
	}
	fs, dropped := s3rules.Detect(sum, s3rules.Options{})
	res := engine.S3Result{Summary: sum, Findings: fs, FindingsDropped: dropped, Matches: entries, Layout: "simple",
		ObjectsScanned: 1, RecordsRead: 2, MatchedRecords: 2, Elapsed: time.Second}
	meta := Meta{Bucket: "log-bucket", Since: t0, Until: t0, GeneratedAt: t0, Narrowed: true}
	return res, meta
}

func TestS3HTML(t *testing.T) {
	res, meta := s3Fixture()
	var buf bytes.Buffer
	if err := S3HTML(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, bad := range []string{"<link", `src="http`, "<script>alert(1)</script>", "x<y>.php"} {
		if strings.Contains(out, bad) {
			t.Errorf("HTML contains %q", bad)
		}
	}
	for _, want := range []string{
		"&lt;script&gt;alert(1)&lt;/script&gt;", "Findings", "Requests over time", "Operations", "Requesters",
		"Top remote IPs", "Top keys", "TLS versions", "Matching requests",
		"Requests", "Errors", "Denied", "Anonymous", "Bytes sent", "Buckets",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	for _, f := range res.Findings {
		if !strings.Contains(out, f.Title) {
			t.Errorf("HTML missing finding %q", f.Title)
		}
	}
}

func TestS3Terminal(t *testing.T) {
	res, meta := s3Fixture()
	var buf bytes.Buffer
	if err := S3Terminal(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Amazon S3 Access Logs", "Requests: 2", "CRITICAL", "Anonymous write or delete succeeded", "OPERATIONS", "REQUESTERS"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal missing %q:\n%s", want, out)
		}
	}
}

func TestS3PDF(t *testing.T) {
	res, meta := s3Fixture()
	d, err := renderS3PDF(res, meta, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Amazon S3 Access Logs", "Findings", "Anonymous write or delete succeeded", "Operations"} {
		if !drawnContains(d, want) {
			t.Errorf("PDF did not draw %q", want)
		}
	}
	if _, err := renderS3PDF(engine.S3Result{}, Meta{}, 10); err != nil {
		t.Fatalf("empty result: %v", err)
	}
}

func TestToneSigV2(t *testing.T) {
	if tone("SigV2") != "warn" || tone("BLOCK") != "crit" || tone("TLSv1.1") != "crit" || tone("403") != "warn" {
		t.Fatal("tone")
	}
}
