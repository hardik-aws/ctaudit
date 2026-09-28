package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

// newTestVPCServer parses serve flags for vpc and builds a server over store.
func newTestVPCServer(t *testing.T, store s3src.ObjectStore, clock *fakeClock, extra ...string) (*server, *bytes.Buffer) {
	t.Helper()
	args := append([]string{"vpc", "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1"}, extra...)
	cfg, err := parseServeArgs(args, clock.now(), io.Discard)
	if err != nil {
		t.Fatalf("parseServeArgs: %v", err)
	}
	var stderr bytes.Buffer
	return newServer(cfg, store, clock.now, &stderr), &stderr
}

func TestServeVPCTickCommitsAndMetrics(t *testing.T) {
	objects := map[string][]byte{testVPCKey: vpcObject(t, vpcAcceptWeb, vpcRejectSSH, vpcExposedSSH)}
	store := &countingStore{MemStore: s3src.NewMemStore(objects)}
	clock := &fakeClock{t: serveNow}
	s, stderr := newTestVPCServer(t, store, clock)

	s.tick(context.Background())
	if !s.state.isSeen(testVPCKey) || !strings.Contains(stderr.String(), "ctaudit serve: vpc tick ok") {
		t.Fatalf("tick not committed: %s", stderr.String())
	}
	h := s.handler()
	text := get(t, h, "/metrics").Body.String()
	for _, want := range []string{
		`ctaudit_vpc_flows_total{action="ACCEPT",subcommand="vpc"} 2`,
		`ctaudit_vpc_flows_total{action="REJECT",subcommand="vpc"} 1`,
		`ctaudit_vpc_bytes_total{subcommand="vpc"} 12360`,
		`ctaudit_vpc_packets_total{subcommand="vpc"} 43`,
		`ctaudit_vpc_findings_total{severity="high",subcommand="vpc"} 1`,
		`ctaudit_vpc_findings_total{severity="critical",subcommand="vpc"} 0`,
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
	if !strings.Contains(get(t, h, "/metrics").Body.String(), `ctaudit_vpc_flows_total{action="ACCEPT",subcommand="vpc"} 2`) {
		t.Error("second tick changed totals for an already-seen key")
	}
}

func TestServeVPCReport(t *testing.T) {
	objects := map[string][]byte{testVPCKey: vpcObject(t, vpcAcceptWeb, vpcRejectSSH)}
	clock := &fakeClock{t: serveNow}
	s, _ := newTestVPCServer(t, s3src.NewMemStore(objects), clock)
	h := s.handler()
	if rec := get(t, h, "/report"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/report before first tick = %d", rec.Code)
	}
	s.tick(context.Background())

	// The exposed-SSH flow arrives in a later object; its finding must be in
	// the merged report.
	later := strings.Replace(testVPCKey, "abcd1234", "efgh5678", 1)
	objects[later] = vpcObject(t, vpcExposedSSH)
	clock.advance(15 * time.Minute)
	s.tick(context.Background())

	rec := get(t, h, "/report")
	page := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(page, "VPC Flow Logs") {
		t.Fatalf("/report = %d", rec.Code)
	}
	if strings.Contains(page, "<link") || strings.Contains(page, `src="http`) {
		t.Error("report is not self-contained")
	}
	if !strings.Contains(page, "Sensitive port reachable from the internet") {
		t.Error("merged report missing the later tick's finding")
	}
}

func TestRunServeVPCFlags(t *testing.T) {
	base := []string{"vpc", "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1"}
	cfg, err := parseServeArgs(append(append([]string{}, base...), "--emit-flows", "all"), serveNow, io.Discard)
	if err != nil || cfg.sub != "vpc" || cfg.vpc == nil || cfg.vpc.EmitFlows != "all" {
		t.Fatalf("--emit-flows under serve: %v %+v", err, cfg)
	}
	for _, flagName := range []string{"--fail-on=high", "--html=x.html", "--since=2026-09-20"} {
		if _, err := parseServeArgs(append(append([]string{}, base...), flagName), serveNow, io.Discard); err == nil {
			t.Errorf("%s accepted by serve vpc", flagName)
		}
	}
}

func TestServeUsageMentionsVPC(t *testing.T) {
	if !strings.Contains(serveUsage, "vpc") {
		t.Errorf("serveUsage = %q", serveUsage)
	}
}
