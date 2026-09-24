package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/s3src"
)

var now = time.Date(2026, 9, 21, 15, 30, 0, 0, time.UTC)

func baseArgs(extra ...string) []string {
	return append([]string{
		"--bucket", "org-cloudtrail-logs",
		"--accounts", "111122223333, 444455556666",
		"--regions", "us-east-1,eu-central-1",
	}, extra...)
}

func TestParseArgsDefaults(t *testing.T) {
	cfg, err := parseArgs(baseArgs(), now)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.Store.Bucket != "org-cloudtrail-logs" {
		t.Errorf("Bucket = %q", cfg.Store.Bucket)
	}
	if got := cfg.Opts.Scope.Accounts; len(got) != 2 || got[1] != "444455556666" {
		t.Errorf("Accounts = %q, want trimmed comma list", got)
	}
	if got := cfg.Meta.Since.Format("2006-01-02"); got != "2026-09-15" {
		t.Errorf("default since = %s, want 2026-09-15 (today minus 6 days)", got)
	}
	if got := cfg.Meta.Until.Format("2006-01-02"); got != "2026-09-21" {
		t.Errorf("default until = %s, want 2026-09-21", got)
	}
	if cfg.HTMLPath != "ctaudit-report.html" || cfg.PDFPath != "" {
		t.Errorf("HTMLPath = %q, PDFPath = %q", cfg.HTMLPath, cfg.PDFPath)
	}
	if cfg.TopN != 10 || cfg.Opts.MaxEvents != 200 {
		t.Errorf("TopN=%d MaxEvents=%d, want 10 and 200", cfg.TopN, cfg.Opts.MaxEvents)
	}
	if cfg.FailOn != nil {
		t.Errorf("FailOn = %v, want nil (none)", *cfg.FailOn)
	}
	if cfg.Meta.Narrowed {
		t.Errorf("Narrowed should be false with no filters")
	}
}

func TestParseArgsTimeWindow(t *testing.T) {
	cfg, err := parseArgs(baseArgs("--since", "2026-09-14", "--until", "2026-09-20"), now)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	day := func(s string) time.Time { d, _ := time.Parse("2006-01-02", s); return d }

	if !cfg.Opts.Filter.Since.Equal(day("2026-09-14")) {
		t.Errorf("Filter.Since = %v", cfg.Opts.Filter.Since)
	}
	// Until is inclusive on the command line and exclusive in the filter.
	if !cfg.Opts.Filter.Until.Equal(day("2026-09-21")) {
		t.Errorf("Filter.Until = %v, want the day after --until", cfg.Opts.Filter.Until)
	}
	// One extra day prefix is scanned to catch events delivered after midnight.
	if !cfg.Opts.Scope.End.Equal(day("2026-09-21")) {
		t.Errorf("Scope.End = %v, want the day after --until", cfg.Opts.Scope.End)
	}
	if cfg.Meta.Days() != 7 {
		t.Errorf("Meta.Days = %d, want 7", cfg.Meta.Days())
	}
}

func TestParseArgsFilters(t *testing.T) {
	cfg, err := parseArgs(baseArgs(
		"--principal", "alice", "--resource", "my-bucket", "--source-ip", "203.0.113.44",
		"--event", "DeleteBucket,PutBucketPolicy", "--source", "s3.amazonaws.com",
		"--errors-only", "--writes-only", "--org-id", "o-abc123", "--prefix", "logs",
		"--fail-on", "high", "--max-events", "50", "--top", "5", "--html", "",
	), now)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	f := cfg.Opts.Filter
	if f.Principal != "alice" || f.Resource != "my-bucket" || f.SourceIP != "203.0.113.44" {
		t.Errorf("substring filters = %+v", f)
	}
	if len(f.Events) != 2 || f.Events[1] != "PutBucketPolicy" || len(f.Sources) != 1 {
		t.Errorf("list filters = %q %q", f.Events, f.Sources)
	}
	if !f.ErrorsOnly || !f.WritesOnly {
		t.Errorf("boolean filters not set")
	}
	if cfg.Opts.Scope.OrgID != "o-abc123" || cfg.Opts.Scope.BasePrefix != "logs" {
		t.Errorf("scope = %+v", cfg.Opts.Scope)
	}
	if cfg.FailOn == nil || *cfg.FailOn != findings.SevHigh {
		t.Errorf("FailOn not parsed as high")
	}
	if cfg.Opts.MaxEvents != 50 || cfg.TopN != 5 || cfg.HTMLPath != "" {
		t.Errorf("MaxEvents=%d TopN=%d HTMLPath=%q", cfg.Opts.MaxEvents, cfg.TopN, cfg.HTMLPath)
	}
	if !cfg.Meta.Narrowed {
		t.Errorf("Narrowed should be true with a principal filter")
	}
}

func TestParseArgsRejectsBadInput(t *testing.T) {
	cases := map[string][]string{
		"missing bucket":    {"--accounts", "111122223333", "--regions", "us-east-1"},
		"missing accounts":  {"--bucket", "b", "--regions", "us-east-1"},
		"missing regions":   {"--bucket", "b", "--accounts", "111122223333"},
		"bad account":       {"--bucket", "b", "--accounts", "1234", "--regions", "us-east-1"},
		"bad date":          baseArgs("--since", "14/09/2026"),
		"since after until": baseArgs("--since", "2026-09-20", "--until", "2026-09-14"),
		"bad fail-on":       baseArgs("--fail-on", "urgent"),
		"bad max-events":    baseArgs("--max-events", "0"),
		"bad top":           baseArgs("--top", "0"),
		"stray argument":    baseArgs("extra"),
		"txt report":        baseArgs("--html", "report.txt"),
		"txt pdf":           baseArgs("--pdf", "report.txt"),
	}
	for name, args := range cases {
		if _, err := parseArgs(args, now); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// memStoreWith returns a store factory serving one root-usage record.
func memStoreWith(t *testing.T) func(context.Context, storeConfig) (s3src.ObjectStore, error) {
	t.Helper()
	body := `{"Records":[{"eventTime":"2026-09-20T10:00:00Z","eventSource":"iam.amazonaws.com",
		"eventName":"CreateAccessKey","awsRegion":"us-east-1","recipientAccountId":"111122223333",
		"userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root"}}]}`
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(body))
	zw.Close()
	key := "AWSLogs/111122223333/CloudTrail/us-east-1/2026/09/20/111122223333_CloudTrail_us-east-1_20260920T1000Z_a.json.gz"
	store := s3src.NewMemStore(map[string][]byte{key: buf.Bytes()})
	return func(context.Context, storeConfig) (s3src.ObjectStore, error) { return store, nil }
}

func runArgs(t *testing.T, newStore storeFactory, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{
		"cloudtrail", "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1",
		"--since", "2026-09-20", "--until", "2026-09-20",
	}, extra...)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr, newStore, now)
	return code, stdout.String(), stderr.String()
}

func TestRunWritesReportsAndExitsZero(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "out.html")
	code, stdout, stderr := runArgs(t, memStoreWith(t), "--html", htmlPath)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "root-usage") || !strings.Contains(stdout, "HTML report written to "+htmlPath) {
		t.Errorf("stdout missing finding or HTML note:\n%s", stdout)
	}
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	if !strings.Contains(string(data), "sev-critical") {
		t.Errorf("html report missing the critical finding")
	}
}

func TestRunFailOn(t *testing.T) {
	if code, _, _ := runArgs(t, memStoreWith(t), "--html", "", "--fail-on", "critical"); code != 1 {
		t.Errorf("critical finding with --fail-on critical: exit = %d, want 1", code)
	}
	if code, _, _ := runArgs(t, memStoreWith(t), "--html", "", "--fail-on", "low"); code != 1 {
		t.Errorf("critical finding with --fail-on low: exit = %d, want 1", code)
	}
	empty := func(context.Context, storeConfig) (s3src.ObjectStore, error) { return s3src.NewMemStore(nil), nil }
	if code, _, _ := runArgs(t, empty, "--html", "", "--fail-on", "low"); code != 0 {
		t.Errorf("no findings: exit = %d, want 0", code)
	}
}

func TestShouldFailOn(t *testing.T) {
	low, critical := findings.SevLow, findings.SevCritical

	cases := []struct {
		name    string
		res     engine.Result
		failOn  *findings.Severity
		wantFal bool
	}{
		{"fail-on none", engine.Result{HasFindings: true, MaxSeverity: critical}, nil, false},
		{
			"no findings at all, even though MaxSeverity's zero value looks like LOW",
			engine.Result{HasFindings: false, MaxSeverity: findings.SevLow}, &low, false,
		},
		{
			"critical finding dropped past the cap must still fail --fail-on critical",
			engine.Result{HasFindings: true, MaxSeverity: critical}, &critical, true,
		},
		{
			"findings present but below the threshold",
			engine.Result{HasFindings: true, MaxSeverity: low}, &critical, false,
		},
	}
	for _, c := range cases {
		if got := shouldFailOn(c.res, c.failOn); got != c.wantFal {
			t.Errorf("%s: shouldFailOn = %v, want %v", c.name, got, c.wantFal)
		}
	}
}

func TestRunExitsTwoOnFailure(t *testing.T) {
	if code, _, stderr := runArgs(t, memStoreWith(t), "--bogus-flag"); code != 2 || stderr == "" {
		t.Errorf("bad flag: exit = %d, stderr = %q", code, stderr)
	}
	broken := func(context.Context, storeConfig) (s3src.ObjectStore, error) {
		return nil, errors.New("no credentials")
	}
	if code, _, stderr := runArgs(t, broken, "--html", ""); code != 2 || !strings.Contains(stderr, "no credentials") {
		t.Errorf("store error: exit = %d, stderr = %q", code, stderr)
	}
	corrupt := func(context.Context, storeConfig) (s3src.ObjectStore, error) {
		key := "AWSLogs/111122223333/CloudTrail/us-east-1/2026/09/20/111122223333_CloudTrail_us-east-1_20260920T1000Z_bad.json.gz"
		return s3src.NewMemStore(map[string][]byte{key: []byte("not gzip")}), nil
	}
	if code, stdout, _ := runArgs(t, corrupt, "--html", ""); code != 2 || !strings.Contains(stdout, "ERRORS (1)") {
		t.Errorf("unreadable object: exit = %d, want 2 with the error listed", code)
	}

	// Errors take precedence over findings: even a CRITICAL finding must not
	// turn an incomplete scan into exit 1 instead of exit 2.
	rootUsageBody := `{"Records":[{"eventTime":"2026-09-20T10:00:00Z","eventSource":"iam.amazonaws.com",
		"eventName":"CreateAccessKey","awsRegion":"us-east-1","recipientAccountId":"111122223333",
		"userIdentity":{"type":"Root","arn":"arn:aws:iam::111122223333:root"}}]}`
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(rootUsageBody))
	zw.Close()
	goodAndCorrupt := func(context.Context, storeConfig) (s3src.ObjectStore, error) {
		goodKey := "AWSLogs/111122223333/CloudTrail/us-east-1/2026/09/20/111122223333_CloudTrail_us-east-1_20260920T1000Z_good.json.gz"
		badKey := "AWSLogs/111122223333/CloudTrail/us-east-1/2026/09/20/111122223333_CloudTrail_us-east-1_20260920T1000Z_bad.json.gz"
		return s3src.NewMemStore(map[string][]byte{
			goodKey: buf.Bytes(),
			badKey:  []byte("not gzip"),
		}), nil
	}
	if code, stdout, _ := runArgs(t, goodAndCorrupt, "--html", "", "--fail-on", "low"); code != 2 {
		t.Errorf("critical finding plus a corrupt object: exit = %d, want 2 (errors precede findings)\nstdout:\n%s", code, stdout)
	}
}

func TestRunHelpExitsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-h"}, &stdout, &stderr, memStoreWith(t), now); code != 0 {
		t.Errorf("-h: exit = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "cloudtrail") || !strings.Contains(stdout.String(), "elb") {
		t.Errorf("top-level usage should list both commands:\n%s", stdout.String())
	}

	for _, cmd := range []string{"cloudtrail", "elb", "alb"} {
		stdout.Reset()
		stderr.Reset()
		if code := run(context.Background(), []string{cmd, "-h"}, &stdout, &stderr, memStoreWith(t), now); code != 0 {
			t.Errorf("%s -h: exit = %d, want 0", cmd, code)
		}
		if !strings.Contains(stderr.String(), "-bucket") {
			t.Errorf("%s -h: flag usage not printed", cmd)
		}
	}
}

func TestRunRequiresCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), nil, &stdout, &stderr, memStoreWith(t), now); code != 2 {
		t.Errorf("no command: exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "Usage: ctaudit <command>") {
		t.Errorf("no command: usage not printed, stderr = %q", stderr.String())
	}

	stderr.Reset()
	// Flags without a command must not silently fall back to CloudTrail.
	if code := run(context.Background(), []string{"--bucket", "b"}, &stdout, &stderr, memStoreWith(t), now); code != 2 {
		t.Errorf("flags without command: exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "--bucket"`) {
		t.Errorf("flags without command: stderr = %q", stderr.String())
	}
}

func TestRunWritesPDF(t *testing.T) {
	dir := t.TempDir()
	pdfPath := filepath.Join(dir, "out.pdf")
	htmlPath := filepath.Join(dir, "out.html")
	code, stdout, stderr := runArgs(t, memStoreWith(t), "--html", htmlPath, "--pdf", pdfPath)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "PDF report written to "+pdfPath) {
		t.Errorf("stdout missing PDF note:\n%s", stdout)
	}
	data, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("read pdf: %v", err)
	}
	if !strings.HasPrefix(string(data), "%PDF-") {
		t.Errorf("pdf report does not start with %%PDF-")
	}
}

func TestRunSkipsPDFByDefault(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := runArgs(t, memStoreWith(t), "--html", filepath.Join(dir, "out.html"))
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.pdf")); len(m) != 0 {
		t.Errorf("unexpected PDF files: %v", m)
	}
}
