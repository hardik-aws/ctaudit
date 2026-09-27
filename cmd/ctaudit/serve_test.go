package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

var serveNow = time.Date(2026, 9, 20, 23, 0, 0, 0, time.UTC)

const serveKeyPrefix = "AWSLogs/111122223333/elasticloadbalancing/us-east-1/2026/09/20/"

func serveKey(name string) string {
	return serveKeyPrefix + "111122223333_elasticloadbalancing_us-east-1_app.tiles.abc_20260920T" + name + "Z_1.2.3.4_x.log.gz"
}

func serveGz(t *testing.T, lines ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(strings.Join(lines, "\n") + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// serveObject is the two-request ALB fixture with the user agent replaced.
func serveObject(t *testing.T, userAgent string) []byte {
	t.Helper()
	fwd := strings.Replace(testALBForward, `"Dart/3.11 (dart:io)"`, `"`+userAgent+`"`, 1)
	return serveGz(t, fwd, testALBNotFound)
}

// countingStore counts Get calls so tests can see which objects a tick read.
type countingStore struct {
	*s3src.MemStore
	gets atomic.Int32
}

func (c *countingStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	c.gets.Add(1)
	return c.MemStore.Get(ctx, key)
}

// fakeClock is a settable now().
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestServer parses serve flags for elb and builds a server over store.
func newTestServer(t *testing.T, store s3src.ObjectStore, clock *fakeClock, extra ...string) (*server, *bytes.Buffer) {
	t.Helper()
	args := append([]string{"elb", "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1"}, extra...)
	cfg, err := parseServeArgs(args, clock.now(), io.Discard)
	if err != nil {
		t.Fatalf("parseServeArgs: %v", err)
	}
	var stderr bytes.Buffer
	return newServer(cfg, store, clock.now, &stderr), &stderr
}

// newTestWAFServer parses serve flags for waf and builds a server over store.
func newTestWAFServer(t *testing.T, store s3src.ObjectStore, clock *fakeClock, extra ...string) (*server, *bytes.Buffer) {
	t.Helper()
	args := append([]string{"waf", "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1"}, extra...)
	cfg, err := parseServeArgs(args, clock.now(), io.Discard)
	if err != nil {
		t.Fatalf("parseServeArgs: %v", err)
	}
	var stderr bytes.Buffer
	return newServer(cfg, store, clock.now, &stderr), &stderr
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestRunServeRejectsFlags(t *testing.T) {
	cases := map[string][]string{
		"since":       {"elb", "--since", "2026-09-20"},
		"until":       {"elb", "--until", "2026-09-20"},
		"html":        {"elb", "--html", "x.html"},
		"pdf":         {"elb", "--pdf", "x.pdf"},
		"pushgateway": {"elb", "--pushgateway", "http://pg:9091"},
		"jsonl":       {"elb", "--jsonl", "x.jsonl"},
		"fail-on":     {"cloudtrail", "--fail-on", "high"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			args := append(args, "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1")
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), append([]string{"serve"}, args...), &stdout, &stderr, elbStore(t), serveNow)
			if code != exitFailed {
				t.Fatalf("exit = %d, want %d", code, exitFailed)
			}
			if !strings.Contains(stderr.String(), "--"+name) {
				t.Errorf("stderr does not name --%s: %s", name, stderr.String())
			}
		})
	}
}

func TestRunServeWAFRejectsFlags(t *testing.T) {
	cases := map[string][]string{
		"since":       {"waf", "--since", "2026-09-20"},
		"until":       {"waf", "--until", "2026-09-20"},
		"html":        {"waf", "--html", "x.html"},
		"pdf":         {"waf", "--pdf", "x.pdf"},
		"pushgateway": {"waf", "--pushgateway", "http://pg:9091"},
		"jsonl":       {"waf", "--jsonl", "x.jsonl"},
		"fail-on":     {"waf", "--fail-on", "high"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			args := append(args, "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1")
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), append([]string{"serve"}, args...), &stdout, &stderr, wafStore(t, wafCleanAllow), serveNow)
			if code != exitFailed {
				t.Fatalf("exit = %d, want %d", code, exitFailed)
			}
			if !strings.Contains(stderr.String(), "--"+name) {
				t.Errorf("stderr does not name --%s: %s", name, stderr.String())
			}
		})
	}
}

func TestRunServeBadDurations(t *testing.T) {
	cases := map[string][]string{
		"interval too short":      {"--interval", "30s"},
		"lookback below interval": {"--interval", "1h", "--lookback", "30m"},
		"lookback too long":       {"--lookback", "721h"},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"serve", "elb", "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1"}, extra...)
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr, elbStore(t), serveNow); code != exitFailed {
				t.Fatalf("exit = %d, want %d; stderr = %s", code, exitFailed, stderr.String())
			}
		})
	}
}

func TestRunServeUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"serve", "vpc"}, &stdout, &stderr, elbStore(t), serveNow); code != exitFailed {
		t.Fatalf("exit = %d, want %d", code, exitFailed)
	}
	if !strings.Contains(stderr.String(), "serve cloudtrail|elb|waf") {
		t.Errorf("stderr missing usage: %s", stderr.String())
	}
}

func TestRunServeBindFailureExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"serve", "elb", "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1", "--listen", "256.0.0.1:0"}
	if code := run(context.Background(), args, &stdout, &stderr, elbStore(t), serveNow); code != exitFailed {
		t.Fatalf("exit = %d, want %d", code, exitFailed)
	}
	if !strings.Contains(stderr.String(), "listen") {
		t.Errorf("stderr missing listen error: %s", stderr.String())
	}
}

func TestRunServeStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	args := []string{"elb", "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1", "--listen", "127.0.0.1:0"}
	if code := runServe(ctx, args, &stdout, &stderr, elbStore(t), func() time.Time { return serveNow }); code != exitOK {
		t.Fatalf("exit = %d, want %d; stderr = %s", code, exitOK, stderr.String())
	}
}

func TestServeTickSkipsSeenKeys(t *testing.T) {
	objects := map[string][]byte{serveKey("1000"): serveObject(t, "Dart/3.11 (dart:io)")}
	store := &countingStore{MemStore: s3src.NewMemStore(objects)}
	clock := &fakeClock{t: serveNow}
	s, stderr := newTestServer(t, store, clock)

	s.tick(context.Background())
	if n := store.gets.Load(); n != 1 {
		t.Fatalf("first tick Get calls = %d, want 1", n)
	}
	if !strings.Contains(stderr.String(), "ctaudit serve: elb tick ok objects=1 records=2 matched=2 errors=0") {
		t.Errorf("first tick line = %q", stderr.String())
	}

	clock.advance(15 * time.Minute)
	s.tick(context.Background())
	if n := store.gets.Load(); n != 1 {
		t.Fatalf("second tick fetched again: Get calls = %d, want 1", n)
	}

	objects[serveKey("1005")] = serveObject(t, "curl/8.0")
	clock.advance(15 * time.Minute)
	s.tick(context.Background())
	if n := store.gets.Load(); n != 2 {
		t.Fatalf("third tick Get calls = %d, want 2 (only the new object)", n)
	}
}

// flakyLoki fails its first push with 400 and accepts the rest.
type flakyLoki struct {
	mu     sync.Mutex
	calls  int
	bodies []string
}

func (f *flakyLoki) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Errorf("gunzip: %v", err)
				return
			}
			body = zr
		}
		b, _ := io.ReadAll(body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		if f.calls == 1 {
			http.Error(w, "invalid push", http.StatusBadRequest)
			return
		}
		f.bodies = append(f.bodies, string(b))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestServeLokiFailureCommitsNothing(t *testing.T) {
	var loki flakyLoki
	lokiSrv := loki.server(t)
	objects := map[string][]byte{serveKey("1000"): serveObject(t, "Dart/3.11 (dart:io)")}
	store := &countingStore{MemStore: s3src.NewMemStore(objects)}
	clock := &fakeClock{t: serveNow}
	s, stderr := newTestServer(t, store, clock, "--loki", lokiSrv.URL)

	s.tick(context.Background())
	if !strings.Contains(stderr.String(), "tick failed") {
		t.Fatalf("Loki 400 should fail the tick: %s", stderr.String())
	}
	if s.state.isSeen(serveKey("1000")) || len(s.state.snapshot()) != 0 {
		t.Fatal("failed tick committed state")
	}
	if rec := get(t, s.handler(), "/report"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/report after failed tick = %d, want 503", rec.Code)
	}

	clock.advance(15 * time.Minute)
	s.tick(context.Background())
	if n := store.gets.Load(); n != 2 {
		t.Errorf("retry tick Get calls = %d, want 2", n)
	}
	if !s.state.isSeen(serveKey("1000")) {
		t.Error("healthy tick did not commit the key")
	}
	loki.mu.Lock()
	defer loki.mu.Unlock()
	if joined := strings.Join(loki.bodies, ""); !strings.Contains(joined, "wp-login.php") {
		t.Errorf("retry did not send the records to Loki: %q", joined)
	}
	// Serve stamps lines with the request time by default.
	reqNS := strconv.FormatInt(time.Date(2026, 9, 20, 10, 1, 26, 379899000, time.UTC).UnixNano(), 10)
	if joined := strings.Join(loki.bodies, ""); !strings.Contains(joined, `"`+reqNS+`"`) {
		t.Errorf("Loki line not stamped with the request time %s: %q", reqNS, joined)
	}
	text := s.state.metrics().Text()
	for _, want := range []string{
		`ctaudit_scans_total{result="failed",subcommand="elb"} 1`,
		`ctaudit_scans_total{result="ok",subcommand="elb"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestServeMetricsAfterTwoTicks(t *testing.T) {
	objects := map[string][]byte{serveKey("1000"): serveObject(t, "Dart/3.11 (dart:io)")}
	clock := &fakeClock{t: serveNow}
	s, _ := newTestServer(t, s3src.NewMemStore(objects), clock)
	h := s.handler()

	s.tick(context.Background())
	objects[serveKey("1005")] = serveObject(t, "curl/8.0")
	clock.advance(15 * time.Minute)
	s.tick(context.Background())

	rec := get(t, h, "/metrics")
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("Content-Type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE ctaudit_scans_total counter",
		`ctaudit_scans_total{result="ok",subcommand="elb"} 2`,
		`ctaudit_scans_total{result="failed",subcommand="elb"} 0`,
		`ctaudit_objects_scanned_total{subcommand="elb"} 2`,
		`ctaudit_records_read_total{subcommand="elb"} 4`,
		`ctaudit_elb_requests_total{status_class="2xx",subcommand="elb"} 2`,
		`ctaudit_elb_requests_total{status_class="4xx",subcommand="elb"} 2`,
		`ctaudit_elb_requests_total{status_class="5xx",subcommand="elb"} 0`,
		`ctaudit_seen_keys{subcommand="elb"} 2`,
		`ctaudit_interval_seconds{subcommand="elb"} 900`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q:\n%s", want, body)
		}
	}
}

func TestServeReport(t *testing.T) {
	objects := map[string][]byte{serveKey("1000"): serveObject(t, "<script>alert(1)</script>")}
	clock := &fakeClock{t: serveNow}
	s, _ := newTestServer(t, s3src.NewMemStore(objects), clock)
	h := s.handler()

	if rec := get(t, h, "/report"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/report before first tick = %d, want 503", rec.Code)
	}
	s.tick(context.Background())

	rec := get(t, h, "/report")
	if rec.Code != http.StatusOK {
		t.Fatalf("/report = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp != reportCSP {
		t.Errorf("CSP = %q", csp)
	}
	page := rec.Body.String()
	if strings.Contains(page, "<link") || strings.Contains(page, `src="http`) {
		t.Error("report is not self-contained")
	}
	if strings.Contains(page, "<script>alert(1)</script>") {
		t.Error("user agent was not escaped")
	}
	if !strings.Contains(page, "2026-09-19") || !strings.Contains(page, "2026-09-20") {
		t.Error("report window missing since/until days")
	}
}

func TestServeHealthzAndNotFound(t *testing.T) {
	s, _ := newTestServer(t, s3src.NewMemStore(nil), &fakeClock{t: serveNow})
	h := s.handler()
	if rec := get(t, h, "/healthz"); rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Errorf("/healthz = %d %q", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/", "/debug/pprof/", "/metricsx"} {
		if rec := get(t, h, path); rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, rec.Code)
		}
	}
}

func TestServeLoopRunsFirstTickAndStops(t *testing.T) {
	objects := map[string][]byte{serveKey("1000"): serveObject(t, "Dart/3.11 (dart:io)")}
	s, _ := newTestServer(t, s3src.NewMemStore(objects), &fakeClock{t: serveNow})
	ctx, cancel := context.WithCancel(context.Background())
	trigger := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		s.loop(ctx, trigger)
		close(done)
	}()
	trigger <- serveNow // accepted only once the first tick has finished
	if n := len(s.state.snapshot()); n != 1 {
		t.Errorf("committed ticks after the first = %d, want 1", n)
	}
	cancel()
	<-done
}

func TestServeWAFTickCommitsAndMetrics(t *testing.T) {
	objects := map[string][]byte{testWAFKey: serveGz(t, wafCleanAllow, wafCleanBlock, wafExploitAllow)}
	store := &countingStore{MemStore: s3src.NewMemStore(objects)}
	clock := &fakeClock{t: serveNow}
	s, stderr := newTestWAFServer(t, store, clock)

	s.tick(context.Background())
	if n := store.gets.Load(); n != 1 {
		t.Fatalf("first tick Get calls = %d, want 1", n)
	}
	if !s.state.isSeen(testWAFKey) {
		t.Fatal("key not seen after commit")
	}
	if !strings.Contains(stderr.String(), "ctaudit serve: waf tick ok") {
		t.Errorf("first tick line = %q", stderr.String())
	}

	text := s.state.metrics().Text()
	for _, want := range []string{
		`ctaudit_waf_requests_total{action="BLOCK",subcommand="waf"} 1`,
		`ctaudit_waf_requests_total{action="ALLOW",subcommand="waf"} 2`,
		`ctaudit_waf_findings_total{severity="critical",subcommand="waf"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q:\n%s", want, text)
		}
	}

	// A second tick over the same key adds nothing: no new Get calls, and
	// the totals are unchanged.
	clock.advance(15 * time.Minute)
	s.tick(context.Background())
	if n := store.gets.Load(); n != 1 {
		t.Fatalf("second tick fetched again: Get calls = %d, want 1", n)
	}
	text = s.state.metrics().Text()
	if !strings.Contains(text, `ctaudit_waf_requests_total{action="ALLOW",subcommand="waf"} 2`) {
		t.Errorf("second tick changed totals for an already-seen key:\n%s", text)
	}
}

func TestServeWAFTickFailsOnListDirsError(t *testing.T) {
	store := listDirsErrStore{s3src.NewMemStore(map[string][]byte{testWAFKey: nil})}
	clock := &fakeClock{t: serveNow}
	s, stderr := newTestWAFServer(t, store, clock)

	s.tick(context.Background())
	if n := len(s.state.snapshot()); n != 0 {
		t.Errorf("committed ticks after a failed tick = %d, want 0", n)
	}
	if !strings.Contains(stderr.String(), "waf tick failed") {
		t.Errorf("stderr does not report the failed tick: %s", stderr.String())
	}
}

func TestServeWAFReport(t *testing.T) {
	objects := map[string][]byte{testWAFKey: serveGz(t, wafCleanAllow, wafCleanBlock)}
	clock := &fakeClock{t: serveNow}
	s, _ := newTestWAFServer(t, s3src.NewMemStore(objects), clock)
	h := s.handler()

	if rec := get(t, h, "/report"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/report before first tick = %d, want 503", rec.Code)
	}
	s.tick(context.Background())

	// A second tick adds a new object under the same web ACL and day whose
	// exploit finding must survive into the merged report.
	objects["AWSLogs/111122223333/WAFLogs/us-east-1/prod-acl/2026/09/20/10/05/c.log.gz"] = serveGz(t, wafExploitAllow)
	clock.advance(15 * time.Minute)
	s.tick(context.Background())

	rec := get(t, h, "/report")
	if rec.Code != http.StatusOK {
		t.Fatalf("/report = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	page := rec.Body.String()
	if strings.Contains(page, "<link") || strings.Contains(page, `src="http`) {
		t.Error("report is not self-contained")
	}
	if !strings.Contains(page, "Matching requests") {
		t.Error("report missing the matching requests section")
	}
	if !strings.Contains(page, "Exploit payload allowed") {
		t.Error("report findings should include the merged tick's exploit finding")
	}
}

func TestServeUsageMentionsWAF(t *testing.T) {
	if !strings.Contains(serveUsage, "waf") {
		t.Errorf("serveUsage = %q, missing waf", serveUsage)
	}
}

// newTestS3Server parses serve flags for s3 (simple layout) and builds a
// server over store.
func newTestS3Server(t *testing.T, store s3src.ObjectStore, clock *fakeClock, extra ...string) (*server, *bytes.Buffer) {
	t.Helper()
	args := append([]string{"s3", "--bucket", "b", "--prefix", "logs/", "--accounts", "111122223333", "--regions", "us-east-1"}, extra...)
	cfg, err := parseServeArgs(args, clock.now(), io.Discard)
	if err != nil {
		t.Fatalf("parseServeArgs: %v", err)
	}
	var stderr bytes.Buffer
	return newServer(cfg, store, clock.now, &stderr), &stderr
}

func TestServeS3TickCommitsAndMetrics(t *testing.T) {
	objects := map[string][]byte{testS3Key: []byte(strings.Join([]string{s3CleanGet, s3CleanList, s3AnonPut}, "\n") + "\n")}
	store := &countingStore{MemStore: s3src.NewMemStore(objects)}
	clock := &fakeClock{t: serveNow}
	s, stderr := newTestS3Server(t, store, clock)

	s.tick(context.Background())
	if n := store.gets.Load(); n != 1 {
		t.Fatalf("first tick Get calls = %d, want 1", n)
	}
	if !s.state.isSeen(testS3Key) || !strings.Contains(stderr.String(), "ctaudit serve: s3 tick ok") {
		t.Fatalf("not committed: %s", stderr.String())
	}
	text := s.state.metrics().Text()
	for _, want := range []string{
		`ctaudit_s3_requests_total{status_class="2xx",subcommand="s3"} 3`,
		`ctaudit_s3_findings_total{severity="critical",subcommand="s3"} 1`,
		`ctaudit_s3_bytes_sent_total{subcommand="s3"} 1000`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q:\n%s", want, text)
		}
	}
	clock.advance(15 * time.Minute)
	s.tick(context.Background())
	if n := store.gets.Load(); n != 1 {
		t.Fatalf("second tick fetched again: Get calls = %d", n)
	}
}

func TestServeS3Report(t *testing.T) {
	objects := map[string][]byte{testS3Key: []byte(s3CleanGet + "\n" + s3AnonPut + "\n")}
	clock := &fakeClock{t: serveNow}
	s, _ := newTestS3Server(t, s3src.NewMemStore(objects), clock, "--requester", "a")
	s.tick(context.Background())
	rec := get(t, s.handler(), "/report")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Anonymous write or delete succeeded") {
		t.Fatalf("status %d:\n%s", rec.Code, rec.Body.String())
	}
}

func TestRunServeS3RejectsFlags(t *testing.T) {
	for _, flagArgs := range [][]string{
		{"--since", "2026-09-01"}, {"--until", "2026-09-20"}, {"--html", "x.html"}, {"--pdf", "x.pdf"},
		{"--pushgateway", "http://p"}, {"--jsonl", "x.jsonl"}, {"--fail-on", "high"},
	} {
		args := append([]string{"s3", "--bucket", "b"}, flagArgs...)
		if _, err := parseServeArgs(args, serveNow, io.Discard); err == nil || !strings.Contains(err.Error(), "not supported by serve") {
			t.Errorf("%v: err = %v", flagArgs, err)
		}
	}
}

func TestServeUsageMentionsS3(t *testing.T) {
	if !strings.Contains(serveUsage, "s3") {
		t.Fatalf("serveUsage = %q", serveUsage)
	}
}
