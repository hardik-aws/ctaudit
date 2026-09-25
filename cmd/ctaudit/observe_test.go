package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

// fakePushgateway records the path and body of every push.
type fakePushgateway struct {
	mu    sync.Mutex
	paths []string
	body  string
	auth  string
}

func (f *fakePushgateway) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.body = string(b)
		f.auth = r.Header.Get("Authorization")
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func readJSONL(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open jsonl: %v", err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad jsonl line %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

func TestRunELBJSONLIsUncapped(t *testing.T) {
	dir := t.TempDir()
	jsonl := filepath.Join(dir, "out.jsonl")
	code, _, stderr := runELBArgs(t, "elb", elbStore(t),
		"--html", "", "--max-events", "1", "--jsonl", jsonl)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	lines := readJSONL(t, jsonl)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (--max-events must not cap the sink)", len(lines))
	}
	runID := lines[0]["run_id"]
	for _, l := range lines {
		if l["kind"] != "request" {
			t.Errorf("kind = %v, want request", l["kind"])
		}
		if l["run_id"] != runID || runID == "" {
			t.Errorf("run_id = %v, want one shared non-empty id", l["run_id"])
		}
	}
}

func TestRunELBPushesMetrics(t *testing.T) {
	var pg fakePushgateway
	srv := pg.server(t)
	t.Setenv("CTAUDIT_PUSHGATEWAY_TOKEN", "s3cret")
	code, _, stderr := runELBArgs(t, "elb", elbStore(t), "--html", "", "--pushgateway", srv.URL)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if len(pg.paths) != 1 || pg.paths[0] != "/metrics/job/ctaudit/subcommand/elb" {
		t.Fatalf("paths = %v", pg.paths)
	}
	if pg.auth != "Bearer s3cret" {
		t.Errorf("Authorization = %q", pg.auth)
	}
	for _, want := range []string{
		"ctaudit_objects_scanned 1\n",
		"ctaudit_records_read 2\n",
		"ctaudit_records_matched 2\n",
		"ctaudit_scan_errors 0\n",
		`ctaudit_elb_requests{status_class="2xx"} 1`,
		`ctaudit_elb_requests{status_class="4xx"} 1`,
		`ctaudit_elb_requests{status_class="5xx"} 0`,
		"ctaudit_last_success_timestamp_seconds ",
		"ctaudit_elb_tls_handshake_max_seconds ",
	} {
		if !strings.Contains(pg.body, want) {
			t.Errorf("push body missing %q:\n%s", want, pg.body)
		}
	}
}

func TestRunCloudTrailPushesFindingCounts(t *testing.T) {
	var pg fakePushgateway
	srv := pg.server(t)
	jsonl := filepath.Join(t.TempDir(), "ct.jsonl")
	code, _, stderr := runArgs(t, memStoreWith(t), "--html", "", "--fail-on", "none",
		"--pushgateway", srv.URL, "--push-job", "audit", "--jsonl", jsonl)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if len(pg.paths) != 1 || pg.paths[0] != "/metrics/job/audit/subcommand/cloudtrail" {
		t.Fatalf("paths = %v", pg.paths)
	}
	for _, want := range []string{
		`ctaudit_findings{severity="critical"} 1`,
		`ctaudit_findings{severity="low"} 0`,
		"ctaudit_findings_dropped 0\n",
	} {
		if !strings.Contains(pg.body, want) {
			t.Errorf("push body missing %q:\n%s", want, pg.body)
		}
	}
	kinds := map[string]int{}
	for _, l := range readJSONL(t, jsonl) {
		kinds[l["kind"].(string)]++
	}
	if kinds["event"] != 1 || kinds["finding"] < 1 {
		t.Errorf("jsonl kinds = %v, want 1 event and at least 1 finding", kinds)
	}
}

func TestRunELBLokiFailureExitsTwo(t *testing.T) {
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "entry too far behind", http.StatusBadRequest)
	}))
	defer loki.Close()
	var pg fakePushgateway
	srv := pg.server(t)

	htmlPath := filepath.Join(t.TempDir(), "elb.html")
	code, _, stderr := runELBArgs(t, "elb", elbStore(t),
		"--html", htmlPath, "--loki", loki.URL, "--pushgateway", srv.URL)
	if code != exitFailed {
		t.Fatalf("exit = %d, want %d; stderr = %s", code, exitFailed, stderr)
	}
	if !strings.Contains(stderr, "loki push") {
		t.Errorf("stderr missing loki error: %s", stderr)
	}
	if _, err := os.Stat(htmlPath); err != nil {
		t.Errorf("HTML report should still be written: %v", err)
	}
	// The run is still pushed, but it must not count as a success.
	if !strings.Contains(pg.body, "ctaudit_last_run_timestamp_seconds ") {
		t.Errorf("push body missing last_run:\n%s", pg.body)
	}
	if strings.Contains(pg.body, "ctaudit_last_success_timestamp_seconds") {
		t.Errorf("failed Loki push must not report success:\n%s", pg.body)
	}
}

func TestRunELBPushgatewayFailureExitsTwo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusBadRequest)
	}))
	defer srv.Close()
	code, _, stderr := runELBArgs(t, "elb", elbStore(t), "--html", "", "--pushgateway", srv.URL)
	if code != exitFailed || !strings.Contains(stderr, "pushgateway push") {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
}

func TestRunObserveBadSettingsFailBeforeScan(t *testing.T) {
	cases := map[string]struct {
		env  map[string]string
		args []string
	}{
		"token and user": {
			env:  map[string]string{"CTAUDIT_LOKI_TOKEN": "t", "CTAUDIT_LOKI_USER": "u"},
			args: []string{"--loki", "http://loki:3100"},
		},
		"bad loki url":        {args: []string{"--loki", "loki:3100"}},
		"bad pushgateway url": {args: []string{"--pushgateway", "ftp://pg"}},
		"bad push job":        {args: []string{"--pushgateway", "http://pg:9091", "--push-job", "a/b"}},
		"bad loki time":       {args: []string{"--loki", "http://loki:3100", "--loki-time", "now"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			called := false
			newStore := func(context.Context, storeConfig) (s3src.ObjectStore, error) {
				called = true
				return nil, nil
			}
			jsonl := filepath.Join(t.TempDir(), "x.jsonl")
			args := append([]string{"--html", "", "--jsonl", jsonl}, tc.args...)
			code, _, stderr := runELBArgs(t, "elb", newStore, args...)
			if code != exitFailed {
				t.Fatalf("exit = %d, stderr = %s", code, stderr)
			}
			if called {
				t.Error("store factory called despite bad settings")
			}
			if _, err := os.Stat(jsonl); !os.IsNotExist(err) {
				t.Errorf("jsonl file should not be created: %v", err)
			}
		})
	}
}

func TestStatusClass(t *testing.T) {
	for in, want := range map[string]string{
		"200": "2xx", "302": "3xx", "404": "4xx", "503": "5xx",
		"101": "other", "-": "other", "": "other", "20": "other",
	} {
		if got := statusClass(in); got != want {
			t.Errorf("statusClass(%q) = %q, want %q", in, got, want)
		}
	}
}
