package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

func TestRunELBNoDebugByDefault(t *testing.T) {
	code, _, stderr := runELBArgs(t, "elb", elbStore(t), "--html", filepath.Join(t.TempDir(), "r.html"))
	if code != exitOK {
		t.Fatalf("exit = %d; stderr = %s", code, stderr)
	}
	if strings.Contains(stderr, "level=DEBUG") {
		t.Errorf("debug lines without --debug:\n%s", stderr)
	}
}

func TestRunELBDebugText(t *testing.T) {
	code, _, stderr := runELBArgs(t, "elb", elbStore(t), "--html", filepath.Join(t.TempDir(), "r.html"), "--debug")
	if code != exitOK {
		t.Fatalf("exit = %d; stderr = %s", code, stderr)
	}
	for _, want := range []string{
		`msg="scan scope" subcommand=elb bucket=b`,
		`msg="listed prefix"`,
		`msg="object read" key=` + testALBKey,
		"records=2 matched=2",
		`msg="scan done" objects=1`,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
}

func TestRunELBDebugFromEnvAsJSON(t *testing.T) {
	t.Setenv("CTAUDIT_DEBUG", "1")
	code, _, stderr := runELBArgs(t, "elb", elbStore(t), "--html", filepath.Join(t.TempDir(), "r.html"), "--log-format", "json")
	if code != exitOK {
		t.Fatalf("exit = %d; stderr = %s", code, stderr)
	}
	msgs := map[string]bool{}
	for _, line := range strings.Split(stderr, "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad JSON debug line %q: %v", line, err)
		}
		msgs[rec["msg"].(string)] = true
	}
	for _, want := range []string{"scan scope", "listed prefix", "object read", "scan done"} {
		if !msgs[want] {
			t.Errorf("no JSON line with msg %q; got %v", want, msgs)
		}
	}
}

func TestRunELBBadLogSettings(t *testing.T) {
	code, _, stderr := runELBArgs(t, "elb", elbStore(t), "--log-format", "xml")
	if code != exitFailed || !strings.Contains(stderr, "--log-format") {
		t.Errorf("bad --log-format: exit %d, stderr %s", code, stderr)
	}
	t.Setenv("CTAUDIT_DEBUG", "maybe")
	code, _, stderr = runELBArgs(t, "elb", elbStore(t))
	if code != exitFailed || !strings.Contains(stderr, "CTAUDIT_DEBUG") {
		t.Errorf("bad CTAUDIT_DEBUG: exit %d, stderr %s", code, stderr)
	}
}

func TestRunELBDebugHidesLokiToken(t *testing.T) {
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer loki.Close()
	t.Setenv("CTAUDIT_LOKI_TOKEN", "sekrit-token")
	code, _, stderr := runELBArgs(t, "elb", elbStore(t), "--html", filepath.Join(t.TempDir(), "r.html"), "--debug", "--loki", loki.URL)
	if code != exitOK {
		t.Fatalf("exit = %d; stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, `msg="http post"`) || !strings.Contains(stderr, `msg="sink closed"`) {
		t.Errorf("stderr missing Loki debug lines:\n%s", stderr)
	}
	for _, leak := range []string{"sekrit-token", "Dart/3.11"} {
		if strings.Contains(stderr, leak) {
			t.Errorf("debug output leaks %q:\n%s", leak, stderr)
		}
	}
}

func TestServeDebugLogsTicksAndRequests(t *testing.T) {
	objects := map[string][]byte{serveKey("1000"): serveObject(t, "Dart/3.11 (dart:io)")}
	clock := &fakeClock{t: serveNow}
	args := []string{"elb", "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1", "--debug"}
	cfg, err := parseServeArgs(args, clock.now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cfg.setLogger(cfg.log.logger(&stderr))
	s := newServer(cfg, s3src.NewMemStore(objects), clock.now, &stderr)

	s.tick(context.Background())
	get(t, s.handler(), "/healthz")
	out := stderr.String()
	for _, want := range []string{
		`msg="tick start" subcommand=elb`,
		"seen_keys=0",
		`msg="object read"`,
		`msg="tick end" result=ok`,
		"committed_keys=1",
		`msg="http request" method=GET path=/healthz status=200`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q:\n%s", want, out)
		}
	}
}
