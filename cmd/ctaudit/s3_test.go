package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

const testS3Key = "logs/2026-09-20-10-30-00-A1B2C3D4E5F6A7B8"

func s3TestLine(ts, ip, requester, op, key string, status int, errCode string, sent int) string {
	return fmt.Sprintf(`79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be data-bucket [%s +0000] %s %s 3E57427F3EXAMPLE %s %s "GET /%s HTTP/1.1" %d %s %d - 10 9 "-" "aws-cli/2.17.0" - hostIdSECRET= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader data-bucket.s3.us-east-1.amazonaws.com TLSv1.2 - -`,
		ts, ip, requester, op, key, key, status, errCode, sent)
}

var (
	s3CleanGet  = s3TestLine("20/Sep/2026:10:15:02", "198.51.100.7", "arn:aws:iam::111122223333:user/alice", "REST.GET.OBJECT", "a.txt", 200, "-", 100)
	s3CleanList = s3TestLine("20/Sep/2026:10:16:02", "198.51.100.7", "arn:aws:iam::111122223333:user/alice", "REST.GET.BUCKET", "-", 200, "-", 900)
	s3DeniedA   = s3TestLine("20/Sep/2026:10:17:00", "192.0.2.50", "arn:aws:iam::111122223333:user/bob", "REST.GET.OBJECT", "s.env", 403, "AccessDenied", 243)
	s3DeniedB   = s3TestLine("20/Sep/2026:10:17:05", "192.0.2.50", "arn:aws:iam::111122223333:user/bob", "REST.GET.OBJECT", "t.env", 403, "AccessDenied", 243)
	s3AnonPut   = s3TestLine("20/Sep/2026:10:18:00", "192.0.2.44", "-", "REST.PUT.OBJECT", "x.php", 200, "-", 0)
	// s3NoStatus has a "-" http_status field, as S3 logs for some malformed
	// or abandoned requests: Status is 0 and it is missing from ByStatus.
	s3NoStatus = fmt.Sprintf(`79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be data-bucket [%s +0000] %s %s 3E57427F3EXAMPLE %s %s "GET /%s HTTP/1.1" - %s %d - 10 9 "-" "aws-cli/2.17.0" - hostIdSECRET= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader data-bucket.s3.us-east-1.amazonaws.com TLSv1.2 - -`,
		"20/Sep/2026:10:19:00", "192.0.2.60", "-", "REST.GET.OBJECT", "u.txt", "u.txt", "-", 0)
)

// s3Store serves lines as one plain-text object under testS3Key.
func s3Store(t *testing.T, lines ...string) storeFactory {
	t.Helper()
	store := s3src.NewMemStore(map[string][]byte{testS3Key: []byte(strings.Join(lines, "\n") + "\n")})
	return func(context.Context, storeConfig) (s3src.ObjectStore, error) { return store, nil }
}

// runS3Args runs the simple layout without --accounts or --regions.
func runS3Args(t *testing.T, newStore storeFactory, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{"s3", "--bucket", "b", "--prefix", "logs/", "--since", "2026-09-20", "--until", "2026-09-20", "--html", ""}, extra...)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr, newStore, now)
	return code, stdout.String(), stderr.String()
}

func TestRunS3CleanDataExitsZero(t *testing.T) {
	code, stdout, stderr := runS3Args(t, s3Store(t, s3CleanGet, s3CleanList))
	if code != exitOK {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	if !strings.Contains(stdout, "Requests: 2") {
		t.Fatalf("stdout = %s", stdout)
	}
}

func TestRunS3AnonymousWriteFailsOn(t *testing.T) {
	if code, _, _ := runS3Args(t, s3Store(t, s3CleanGet, s3AnonPut)); code != exitFindings {
		t.Fatalf("default --fail-on critical: exit %d", code)
	}
	if code, _, _ := runS3Args(t, s3Store(t, s3CleanGet, s3AnonPut), "--fail-on", "none"); code != exitOK {
		t.Fatalf("--fail-on none: exit %d", code)
	}
}

func TestRunS3DeniedThresholdFailsOnHigh(t *testing.T) {
	store := s3Store(t, s3DeniedA, s3DeniedB)
	if code, _, _ := runS3Args(t, store, "--fail-on", "high", "--denied-threshold", "2"); code != exitFindings {
		t.Fatalf("exit %d", code)
	}
	if code, _, _ := runS3Args(t, store, "--fail-on", "high"); code != exitOK {
		t.Fatalf("default threshold: exit %d", code)
	}
}

func TestRunS3ExitsTwoOnUnreadableObject(t *testing.T) {
	store := s3src.NewMemStore(map[string][]byte{testS3Key: []byte("\x1f\x8bxx")})
	code, _, _ := runS3Args(t, func(context.Context, storeConfig) (s3src.ObjectStore, error) { return store, nil })
	if code != exitFailed {
		t.Fatalf("exit %d", code)
	}
}

func TestRunS3WritesHTMLPDFAndJSONL(t *testing.T) {
	dir := t.TempDir()
	html, pdf, jsonl := filepath.Join(dir, "s.html"), filepath.Join(dir, "s.pdf"), filepath.Join(dir, "s.jsonl")
	code, _, stderr := runS3Args(t, s3Store(t, s3CleanGet, s3AnonPut), "--html", html, "--pdf", pdf, "--jsonl", jsonl, "--fail-on", "none")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	b, err := os.ReadFile(html)
	if err != nil || strings.Contains(string(b), "<link") || strings.Contains(string(b), "hostIdSECRET") {
		t.Fatalf("html: %v", err)
	}
	if fi, err := os.Stat(pdf); err != nil || fi.Size() == 0 {
		t.Fatalf("pdf: %v", err)
	}
	lines, _ := os.ReadFile(jsonl)
	if n := strings.Count(string(lines), `"kind":"request"`); n != 2 {
		t.Fatalf("jsonl request lines = %d:\n%s", n, lines)
	}
	if !strings.Contains(string(lines), `"kind":"finding"`) {
		t.Fatalf("jsonl has no finding lines:\n%s", lines)
	}
}

func TestRunS3Filters(t *testing.T) {
	code, stdout, _ := runS3Args(t, s3Store(t, s3CleanGet, s3CleanList, s3DeniedA), "--status", "4xx", "--requester", "bob", "--errors-only")
	if code != exitOK || !strings.Contains(stdout, "Matched: 1") {
		t.Fatalf("exit %d:\n%s", code, stdout)
	}
}

func TestRunS3PartitionedNeedsAccounts(t *testing.T) {
	code, _, stderr := runS3Args(t, s3Store(t, s3CleanGet), "--layout", "partitioned")
	if code != exitFailed || !strings.Contains(stderr, "--accounts is required") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	key := "logs/111122223333/us-east-1/data-bucket/2026/09/20/2026-09-20-10-30-00-A1B2C3D4E5F6A7B8"
	store := s3src.NewMemStore(map[string][]byte{key: []byte(s3CleanGet + "\n")})
	code, stdout, stderr := runS3Args(t, func(context.Context, storeConfig) (s3src.ObjectStore, error) { return store, nil },
		"--layout", "partitioned", "--accounts", "111122223333", "--regions", "us-east-1", "--source-buckets", "data")
	if code != exitOK || !strings.Contains(stdout, "Requests: 1") {
		t.Fatalf("exit %d: %s\n%s", code, stderr, stdout)
	}
}

func TestRunS3BadFlagsExitTwo(t *testing.T) {
	for _, args := range [][]string{
		{"--layout", "flat"},
		{"--status", "20x"},
		{"--denied-threshold", "0"},
		{"--delete-threshold", "-1"},
		{"--egress-threshold", "0"},
		{"--fail-on", "urgent"},
		{"--pdf", "report.txt"},
	} {
		if code, _, _ := runS3Args(t, s3Store(t, s3CleanGet), args...); code != exitFailed {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestRunS3WarnsWhenNothingFound(t *testing.T) {
	store := s3src.NewMemStore(nil)
	_, _, stderr := runS3Args(t, func(context.Context, storeConfig) (s3src.ObjectStore, error) { return store, nil })
	if !strings.Contains(stderr, "no S3 access log objects found") || !strings.Contains(stderr, "s3://b/logs/2026-09-20-") {
		t.Fatalf("stderr = %s", stderr)
	}
}

func TestRunHelpListsS3(t *testing.T) {
	var stdout bytes.Buffer
	run(context.Background(), []string{"help"}, &stdout, &bytes.Buffer{}, nil, now)
	if !strings.Contains(stdout.String(), "s3           scan Amazon S3 server access logs") {
		t.Fatalf("usage = %s", stdout.String())
	}
}
