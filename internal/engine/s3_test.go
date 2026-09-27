package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/s3log"
	"github.com/gsmappdev/ctaudit/internal/s3src"
)

// s3Line builds one access log line in the current 26-field format.
// requester "-" is anonymous; errCode "-" is none.
func s3Line(ts, ip, requester, op, key, uri string, status int, errCode string, sent int) string {
	return fmt.Sprintf(`79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be data-bucket [%s +0000] %s %s 3E57427F3EXAMPLE %s %s "%s" %d %s %d - 10 9 "-" "aws-cli/2.17.0" - hostIdSECRET= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader data-bucket.s3.us-east-1.amazonaws.com TLSv1.2 - -`,
		ts, ip, requester, op, key, uri, status, errCode, sent)
}

const alice = "arn:aws:iam::111122223333:user/alice"

var (
	s3Get     = s3Line("20/Sep/2026:10:15:02", "198.51.100.7", alice, "REST.GET.OBJECT", "a.txt", "GET /a.txt HTTP/1.1", 200, "-", 100)
	s3Denied  = s3Line("20/Sep/2026:10:16:00", "192.0.2.50", alice, "REST.GET.OBJECT", "s.env", "GET /s.env HTTP/1.1", 403, "AccessDenied", 243)
	s3AnonPut = s3Line("20/Sep/2026:10:17:00", "192.0.2.44", "-", "REST.PUT.OBJECT", "x.php", "PUT /x.php HTTP/1.1", 200, "-", 0)
	// s3Late is after the window when Until is 2026-09-21T00:00Z.
	s3Late = s3Line("21/Sep/2026:01:00:00", "198.51.100.7", alice, "REST.GET.OBJECT", "b.txt", "GET /b.txt HTTP/1.1", 200, "-", 5)
)

func s3Opts(layout string) S3Options {
	start := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	return S3Options{
		Scope:  s3src.Scope{BasePrefix: "logs/", Start: start, End: start.AddDate(0, 0, 1)},
		Layout: layout,
		Filter: s3log.Filter{Since: start, Until: start.AddDate(0, 0, 1)},
	}
}

func simpleStore(objects map[string]string) *s3src.MemStore {
	m := map[string][]byte{}
	for k, v := range objects {
		m[k] = []byte(v)
	}
	return s3src.NewMemStore(m)
}

func TestRunS3Simple(t *testing.T) {
	store := simpleStore(map[string]string{
		"logs/2026-09-20-10-20-00-A1B2C3D4E5F6A7B8": strings.Join([]string{s3Get, s3Denied, s3AnonPut}, "\n") + "\n",
		"logs/2026-09-21-01-05-00-B1B2C3D4E5F6A7B8": s3Late + "\n",
		"logs/readme.txt": "not a log",
		"other/2026-09-20-10-20-00-C1B2C3D4E5F6A7B8": s3Get + "\n",
	})
	res, err := RunS3(context.Background(), store, s3Opts(""))
	if err != nil {
		t.Fatal(err)
	}
	if res.Layout != s3src.S3LayoutSimple || res.Prefixes != 2 || res.FirstPrefix != "logs/2026-09-20-" {
		t.Fatalf("layout/prefixes: %q %d %q", res.Layout, res.Prefixes, res.FirstPrefix)
	}
	if res.ObjectsScanned != 2 || res.RecordsRead != 4 || res.MatchedRecords != 3 || res.Summary.Total != 3 {
		t.Fatalf("counts: objects %d read %d matched %d total %d", res.ObjectsScanned, res.RecordsRead, res.MatchedRecords, res.Summary.Total)
	}
	if len(res.Findings) == 0 || res.Findings[0].Rule != "s3-anonymous-write" {
		t.Fatalf("findings: %+v", res.Findings)
	}
	if len(res.Errors) != 0 || len(res.ReadKeys) != 2 {
		t.Fatalf("errors %v, read keys %v", res.Errors, res.ReadKeys)
	}
}

func TestRunS3FilterMaxEventsAndEmit(t *testing.T) {
	store := simpleStore(map[string]string{
		"logs/2026-09-20-10-20-00-A1B2C3D4E5F6A7B8": strings.Join([]string{s3AnonPut, s3Denied, s3Get}, "\n") + "\n",
	})
	opts := s3Opts(s3src.S3LayoutSimple)
	opts.MaxEvents = 1
	var mu sync.Mutex
	var emitted int
	opts.Emit = func() func(s3log.Entry) {
		return func(s3log.Entry) { mu.Lock(); emitted++; mu.Unlock() }
	}
	res, err := RunS3(context.Background(), store, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 || res.Matches[0].Operation != "REST.GET.OBJECT" || res.Matches[0].Status != 200 || emitted != 3 || res.Summary.Total != 3 {
		t.Fatalf("matches %+v, emitted %d, total %d", res.Matches, emitted, res.Summary.Total)
	}

	opts = s3Opts(s3src.S3LayoutSimple)
	opts.Filter.Statuses = []string{"4xx"}
	res, _ = RunS3(context.Background(), store, opts)
	if res.MatchedRecords != 1 || res.Summary.Denied != 1 {
		t.Fatalf("status filter: matched %d", res.MatchedRecords)
	}
}

func TestRunS3Partitioned(t *testing.T) {
	store := simpleStore(map[string]string{
		"logs/111122223333/us-east-1/data-bucket/2026/09/20/2026-09-20-10-20-00-A1B2C3D4E5F6A7B8": s3Get + "\n",
		"logs/111122223333/us-east-1/web-assets/2026/09/20/2026-09-20-10-20-00-B1B2C3D4E5F6A7B8":  s3Denied + "\n",
	})
	opts := s3Opts(s3src.S3LayoutPartitioned)
	opts.Scope.Accounts, opts.Scope.Regions = []string{"111122223333"}, []string{"us-east-1"}
	opts.SourceBuckets = []string{"data"}
	res, err := RunS3(context.Background(), store, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SourceBuckets) != 1 || res.SourceBuckets[0] != "data-bucket" || res.ObjectsScanned != 1 || res.MatchedRecords != 1 {
		t.Fatalf("partitioned: buckets %v objects %d matched %d", res.SourceBuckets, res.ObjectsScanned, res.MatchedRecords)
	}

	opts.Scope.Accounts = nil
	if _, err := RunS3(context.Background(), store, opts); err == nil || !strings.Contains(err.Error(), "empty scan scope") {
		t.Fatalf("partitioned without accounts: err = %v", err)
	}
}

type s3DirsErrStore struct{ *s3src.MemStore }

func (s3DirsErrStore) ListDirs(context.Context, string) ([]string, error) {
	return nil, errors.New("access denied")
}

func TestRunS3Errors(t *testing.T) {
	store := simpleStore(map[string]string{
		"logs/2026-09-20-10-20-00-A1B2C3D4E5F6A7B8": s3Get + "\n",
		"logs/2026-09-20-10-25-00-B1B2C3D4E5F6A7B8": "\x1f\x8bxx",
	})
	res, err := RunS3(context.Background(), store, s3Opts(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 1 || res.MatchedRecords != 1 {
		t.Fatalf("errors %v matched %d", res.Errors, res.MatchedRecords)
	}

	opts := s3Opts(s3src.S3LayoutPartitioned)
	opts.Scope.Accounts, opts.Scope.Regions = []string{"111122223333"}, []string{"us-east-1"}
	if _, err := RunS3(context.Background(), s3DirsErrStore{s3src.NewMemStore(nil)}, opts); err == nil {
		t.Fatal("a failed discovery listing must fail the scan")
	}

	bad := s3Opts("flat")
	if _, err := RunS3(context.Background(), store, bad); err == nil || !strings.Contains(err.Error(), "unknown S3 log layout") {
		t.Fatalf("bad layout: err = %v", err)
	}
	inverted := s3Opts("")
	inverted.Scope.End = inverted.Scope.Start.AddDate(0, 0, -1)
	if _, err := RunS3(context.Background(), store, inverted); err == nil || !strings.Contains(err.Error(), "empty scan scope") {
		t.Fatalf("inverted range: err = %v", err)
	}
	empty, err := RunS3(context.Background(), s3src.NewMemStore(nil), s3Opts(""))
	if err != nil || empty.ObjectsScanned != 0 || empty.Prefixes != 2 {
		t.Fatalf("empty bucket: %+v %v", empty, err)
	}
}
