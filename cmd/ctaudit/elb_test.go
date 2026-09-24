package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/s3src"
)

const (
	testALBKey = "AWSLogs/111122223333/elasticloadbalancing/us-east-1/2026/09/20/" +
		"111122223333_elasticloadbalancing_us-east-1_app.tiles.abc_20260920T1000Z_1.2.3.4_x.log.gz"

	testALBForward  = `https 2026-09-20T10:00:47.805298Z app/tiles/abc 78.190.26.165:5815 10.20.20.37:80 0.001 0.003 0.000 200 200 153 3860 "GET https://tile.example.com:443/data/roads.json HTTP/1.1" "Dart/3.11 (dart:io)" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/tiles/ce53 "Root=1-6ab37ca3-72b3ccd0353538ac305db394" "tile.example.com" "arn:aws:acm:us-east-1:111122223333:certificate/34ec" 2 2026-09-20T10:00:47.801000Z "forward" "-" "-" "10.20.20.37:80" "200" "-" "-" TID_d7917035eabacb42bea251b01fb60ab4 "-" "-" "-" 100.51.96.60 "-" "-"`
	testALBNotFound = `http 2026-09-20T10:01:26.379899Z app/tiles/abc 216.180.246.224:21790 - -1 -1 -1 404 - 127 162 "GET http://tiles.elb.amazonaws.com:80/wp-login.php HTTP/1.0" "GenomeCrawlerd/1.0" - - - "Root=1-6ab37c8e-5afd1aca560fd3a825162993" "-" "-" 0 2026-09-20T10:01:26.379000Z "fixed-response" "-" "-" "-" "-" "-" "-" TID_558e26a7adede44b9fdb98006014afcf "-" "-" "-" 100.51.96.60 "-" "-"`
)

func elbStore(t *testing.T) storeFactory {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(testALBForward + "\n" + testALBNotFound + "\n"))
	zw.Close()
	store := s3src.NewMemStore(map[string][]byte{testALBKey: buf.Bytes()})
	return func(context.Context, storeConfig) (s3src.ObjectStore, error) { return store, nil }
}

func runELBArgs(t *testing.T, cmd string, newStore storeFactory, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{
		cmd, "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1",
		"--since", "2026-09-20", "--until", "2026-09-20",
	}, extra...)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr, newStore, now)
	return code, stdout.String(), stderr.String()
}

func TestParseELBArgs(t *testing.T) {
	cfg, err := parseELBArgs(baseArgs(), now)
	if err != nil {
		t.Fatalf("parseELBArgs: %v", err)
	}
	if cfg.HTMLPath != "elb-report.html" || cfg.PDFPath != "" || cfg.TopN != 10 || cfg.Opts.MaxEvents != 200 {
		t.Errorf("defaults: HTMLPath=%q TopN=%d MaxEvents=%d", cfg.HTMLPath, cfg.TopN, cfg.Opts.MaxEvents)
	}
	if cfg.Opts.Scope.Service != s3src.ServiceELB {
		t.Errorf("Scope.Service = %q, want %q", cfg.Opts.Scope.Service, s3src.ServiceELB)
	}
	if cfg.Meta.Narrowed {
		t.Errorf("Narrowed should be false with no filters")
	}

	cfg, err = parseELBArgs(baseArgs(
		"--until", "2026-09-20", "--lb", "tiles, api", "--type", "alb,network",
		"--client-ip", "10.0.", "--host", "tile", "--path", "/data", "--method", "GET,POST",
		"--status", "5xx,404", "--target", "10.20", "--user-agent", "dart", "--slower-than", "250ms",
	), now)
	if err != nil {
		t.Fatalf("parseELBArgs with filters: %v", err)
	}
	f := cfg.Opts.Filter
	if f.ClientIP != "10.0." || f.Host != "tile" || f.Path != "/data" || f.Target != "10.20" || f.UserAgent != "dart" {
		t.Errorf("substring filters = %+v", f)
	}
	if len(f.Methods) != 2 || len(f.Statuses) != 2 || f.SlowerThan != 250*time.Millisecond {
		t.Errorf("list/duration filters = %q %q %v", f.Methods, f.Statuses, f.SlowerThan)
	}
	if len(cfg.Opts.LBs) != 2 || cfg.Opts.LBs[1] != "api" {
		t.Errorf("LBs = %q", cfg.Opts.LBs)
	}
	if len(cfg.Opts.Kinds) != 2 || cfg.Opts.Kinds[0] != elblog.ALB || cfg.Opts.Kinds[1] != elblog.NLB {
		t.Errorf("Kinds = %v", cfg.Opts.Kinds)
	}
	day := func(s string) time.Time { d, _ := time.Parse(dayLayout, s); return d }
	if !f.Until.Equal(day("2026-09-21")) || !cfg.Opts.Scope.End.Equal(day("2026-09-21")) {
		t.Errorf("Filter.Until=%v Scope.End=%v, want the day after --until", f.Until, cfg.Opts.Scope.End)
	}
	if !cfg.Meta.Narrowed {
		t.Errorf("Narrowed should be true with filters")
	}

	// A load balancer name alone narrows the report too.
	cfg, err = parseELBArgs(baseArgs("--lb", "tiles"), now)
	if err != nil || !cfg.Meta.Narrowed {
		t.Errorf("--lb alone: err=%v Narrowed=%v, want narrowed", err, cfg.Meta.Narrowed)
	}
}

func TestParseELBArgsRejectsBadInput(t *testing.T) {
	cases := map[string][]string{
		"missing bucket":       {"--accounts", "111122223333", "--regions", "us-east-1"},
		"bad account":          {"--bucket", "b", "--accounts", "12", "--regions", "us-east-1"},
		"bad type":             baseArgs("--type", "gateway"),
		"bad slower-than":      baseArgs("--slower-than", "fast"),
		"negative slower-than": baseArgs("--slower-than", "-1s"),
		"bad max-events":       baseArgs("--max-events", "0"),
		"txt report":           baseArgs("--html", "r.txt"),
		"txt pdf":              baseArgs("--pdf", "r.txt"),
		"cloudtrail-only flag": baseArgs("--principal", "alice"),
		"stray argument":       baseArgs("extra"),
	}
	for name, args := range cases {
		if _, err := parseELBArgs(args, now); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestRunELBWritesReports(t *testing.T) {
	for _, cmd := range []string{"elb", "alb"} {
		htmlPath := filepath.Join(t.TempDir(), "elb.html")
		code, stdout, stderr := runELBArgs(t, cmd, elbStore(t), "--html", htmlPath)
		if code != 0 {
			t.Fatalf("%s: exit = %d, stderr = %s", cmd, code, stderr)
		}
		for _, want := range []string{"TRAFFIC", "tile.example.com", "ECDHE-RSA-AES128-GCM-SHA256", "HTML report written to " + htmlPath} {
			if !strings.Contains(stdout, want) {
				t.Errorf("%s: stdout missing %q:\n%s", cmd, want, stdout)
			}
		}
		if strings.Contains(stdout, "MATCHING REQUESTS") {
			t.Errorf("%s: unfiltered run should not print the matching-requests table", cmd)
		}
		data, err := os.ReadFile(htmlPath)
		if err != nil {
			t.Fatalf("%s: read html: %v", cmd, err)
		}
		if !strings.Contains(string(data), "tile.example.com") {
			t.Errorf("%s: html report missing host", cmd)
		}
	}
}

func TestRunELBFilters(t *testing.T) {
	code, stdout, stderr := runELBArgs(t, "elb", elbStore(t), "--html", "", "--status", "404")
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "MATCHING REQUESTS") || !strings.Contains(stdout, "wp-login.php") {
		t.Errorf("404 filter should list the wp-login request:\n%s", stdout)
	}
	if strings.Contains(stdout, "roads.json") {
		t.Errorf("404 filter should exclude the 200 request:\n%s", stdout)
	}

	// A kind filter that excludes every object scans nothing and warns.
	code, _, stderr = runELBArgs(t, "elb", elbStore(t), "--html", "", "--type", "nlb")
	if code != 0 {
		t.Fatalf("--type nlb: exit = %d", code)
	}
	if !strings.Contains(stderr, "no log objects found") || !strings.Contains(stderr, "elasticloadbalancing") {
		t.Errorf("--type nlb: want an empty-scan warning naming the ELB prefix, stderr = %q", stderr)
	}
}

func TestRunELBExitsTwoOnUnreadableObject(t *testing.T) {
	corrupt := func(context.Context, storeConfig) (s3src.ObjectStore, error) {
		return s3src.NewMemStore(map[string][]byte{testALBKey: []byte("not gzip")}), nil
	}
	if code, stdout, _ := runELBArgs(t, "elb", corrupt, "--html", ""); code != 2 || !strings.Contains(stdout, "ERRORS (1)") {
		t.Errorf("unreadable object: exit = %d, want 2 with the error listed\n%s", code, stdout)
	}
}

func TestRunELBWritesPDF(t *testing.T) {
	dir := t.TempDir()
	pdfPath := filepath.Join(dir, "out.PDF")
	code, stdout, stderr := runELBArgs(t, "elb", elbStore(t), "--html", "", "--pdf", pdfPath)
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

func TestRunELBSkipsPDFByDefault(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := runELBArgs(t, "elb", elbStore(t), "--html", filepath.Join(dir, "r.html"))
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if strings.Contains(stdout, "PDF report") {
		t.Errorf("stdout mentions a PDF without --pdf:\n%s", stdout)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.pdf")); len(m) != 0 {
		t.Errorf("unexpected PDF files: %v", m)
	}
}

func TestRunELBPDFWriteFailureExitsTwo(t *testing.T) {
	pdfPath := filepath.Join(t.TempDir(), "missing", "out.pdf")
	code, _, stderr := runELBArgs(t, "elb", elbStore(t), "--html", "", "--pdf", pdfPath)
	if code != 2 || !strings.Contains(stderr, "create report") {
		t.Errorf("exit = %d, stderr = %s", code, stderr)
	}
}
