package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/flowlog"
	"github.com/gsmappdev/ctaudit/internal/s3src"
)

const (
	testVPCKey = "AWSLogs/111122223333/vpcflowlogs/us-east-1/2026/09/20/111122223333_vpcflowlogs_us-east-1_fl-0123456789abcdef0_20260920T1030Z_abcd1234.log.gz"

	vpcTestHeader = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"
	// vpcAcceptWeb and vpcRejectSSH produce no findings at the defaults.
	vpcAcceptWeb = "2 111122223333 eni-0a1b2c3d4e5f60718 198.51.100.7 10.0.1.10 51544 443 6 12 5120 1789900000 1789900060 ACCEPT OK"
	vpcRejectSSH = "2 111122223333 eni-0a1b2c3d4e5f60718 203.0.113.9 10.0.1.10 40001 22 6 1 40 1789900010 1789900070 REJECT OK"
	// vpcExposedSSH is an accepted SSH flow from a public source to a
	// private host: a vpc-sensitive-port-exposed (HIGH) finding.
	vpcExposedSSH = "2 111122223333 eni-0b2c3d4e5f6071829 203.0.113.50 10.0.1.20 50505 22 6 30 7200 1789900020 1789900080 ACCEPT OK"
)

func vpcObject(t *testing.T, lines ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(vpcTestHeader + "\n" + strings.Join(lines, "\n") + "\n"))
	zw.Close()
	return buf.Bytes()
}

func vpcStoreOf(objects map[string][]byte) storeFactory {
	store := s3src.NewMemStore(objects)
	return func(context.Context, storeConfig) (s3src.ObjectStore, error) { return store, nil }
}

func vpcStore(t *testing.T, lines ...string) storeFactory {
	return vpcStoreOf(map[string][]byte{testVPCKey: vpcObject(t, lines...)})
}

func runVPCArgs(t *testing.T, newStore storeFactory, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{
		"vpc", "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1",
		"--since", "2026-09-20", "--until", "2026-09-20", "--html", "",
	}, extra...)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr, newStore, now)
	return code, stdout.String(), stderr.String()
}

func TestRunVPCCleanExitsZero(t *testing.T) {
	code, stdout, stderr := runVPCArgs(t, vpcStore(t, vpcAcceptWeb, vpcRejectSSH))
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "VPC Flow Logs") || !strings.Contains(stdout, "FINDINGS (0)") {
		t.Errorf("stdout = %s", stdout)
	}
}

func TestRunVPCFindingFailsOn(t *testing.T) {
	store := vpcStore(t, vpcAcceptWeb, vpcExposedSSH)
	if code, _, stderr := runVPCArgs(t, store); code != exitFindings {
		t.Fatalf("default --fail-on high: exit = %d, stderr = %s", code, stderr)
	}
	if code, _, _ := runVPCArgs(t, store, "--fail-on", "critical"); code != exitOK {
		t.Fatalf("--fail-on critical: exit = %d", code)
	}
	if code, _, _ := runVPCArgs(t, store, "--fail-on", "none"); code != exitOK {
		t.Fatalf("--fail-on none: exit = %d", code)
	}
}

func TestRunVPCExitsTwoOnUnreadableObject(t *testing.T) {
	bad := strings.Replace(testVPCKey, "abcd1234", "bad", 1)
	store := vpcStoreOf(map[string][]byte{testVPCKey: vpcObject(t, vpcAcceptWeb), bad: []byte("\x1f\x8bxx")})
	code, _, stderr := runVPCArgs(t, store, "--fail-on", "none")
	if code != exitFailed {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
}

func TestRunVPCExitsTwoOnHiveLayout(t *testing.T) {
	hive := "AWSLogs/aws-account-id=111122223333/aws-service=vpcflowlogs/aws-region=us-east-1/year=2026/month=09/day=20/hour=10/111122223333_vpcflowlogs_us-east-1_fl-1_20260920T1000Z_x.log.gz"
	code, _, stderr := runVPCArgs(t, vpcStoreOf(map[string][]byte{hive: vpcObject(t, vpcAcceptWeb)}))
	if code != exitFailed || !strings.Contains(stderr, "Hive-compatible") {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
}

func TestRunVPCEmitFlows(t *testing.T) {
	for mode, wantFlows := range map[string]int{"": 1, "reject": 1, "all": 3, "none": 0} {
		path := filepath.Join(t.TempDir(), "out.jsonl")
		extra := []string{"--fail-on", "none", "--jsonl", path}
		if mode != "" {
			extra = append(extra, "--emit-flows", mode)
		}
		code, _, stderr := runVPCArgs(t, vpcStore(t, vpcAcceptWeb, vpcRejectSSH, vpcExposedSSH), extra...)
		if code != exitOK {
			t.Fatalf("mode %q: exit = %d, stderr = %s", mode, code, stderr)
		}
		flows, findingLines := 0, 0
		for _, m := range readJSONL(t, path) {
			switch m["kind"] {
			case "flow":
				flows++
				if mode != "all" && m["action"] == "ACCEPT" {
					t.Errorf("mode %q emitted %v", mode, m["action"])
				}
			case "finding":
				findingLines++
			}
		}
		if flows != wantFlows || findingLines != 1 {
			t.Errorf("mode %q: flows %d (want %d), findings %d (want 1)", mode, flows, wantFlows, findingLines)
		}
	}
}

func TestRunVPCWritesHTMLAndPDF(t *testing.T) {
	dir := t.TempDir()
	html, pdf := filepath.Join(dir, "vpc.html"), filepath.Join(dir, "vpc.pdf")
	code, stdout, stderr := runVPCArgs(t, vpcStore(t, vpcAcceptWeb), "--html", html, "--pdf", pdf)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	b, err := os.ReadFile(html)
	if err != nil || !bytes.Contains(b, []byte("VPC Flow Logs")) {
		t.Fatalf("html: %v", err)
	}
	if p, err := os.ReadFile(pdf); err != nil || !bytes.HasPrefix(p, []byte("%PDF-")) {
		t.Fatalf("pdf: %v", err)
	}
	if !strings.Contains(stdout, "HTML report written to") || !strings.Contains(stdout, "PDF report written to") {
		t.Errorf("stdout = %s", stdout)
	}
}

func TestRunVPCPushesMetrics(t *testing.T) {
	var pg fakePushgateway
	srv := pg.server(t)
	code, _, stderr := runVPCArgs(t, vpcStore(t, vpcAcceptWeb, vpcRejectSSH, vpcExposedSSH),
		"--fail-on", "none", "--pushgateway", srv.URL)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if len(pg.paths) != 1 || pg.paths[0] != "/metrics/job/ctaudit/subcommand/vpc" {
		t.Fatalf("paths = %v", pg.paths)
	}
	for _, want := range []string{
		`ctaudit_vpc_flows{action="ACCEPT"} 2`,
		`ctaudit_vpc_flows{action="REJECT"} 1`,
		"ctaudit_vpc_bytes 12360\n",
		"ctaudit_vpc_packets 43\n",
		`ctaudit_vpc_findings{severity="high"} 1`,
		`ctaudit_vpc_findings{severity="critical"} 0`,
	} {
		if !strings.Contains(pg.body, want) {
			t.Errorf("push body missing %q:\n%s", want, pg.body)
		}
	}
}

func TestParseVPCArgs(t *testing.T) {
	cfg, _, err := parseVPCArgsFlags([]string{"--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1",
		"--since", "2026-09-20", "--until", "2026-09-20"}, now, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EmitFlows != "reject" || cfg.FailOn != findings.SevHigh || cfg.FailOff || cfg.HTMLPath != "vpc-report.html" ||
		cfg.Opts.MaxEvents != 200 || cfg.Opts.Rules.ScanPorts != 25 || cfg.Opts.Rules.SweepHosts != 50 ||
		cfg.Opts.Rules.EgressBytes != 1<<30 || cfg.Opts.Scope.Service != s3src.ServiceVPC || cfg.Meta.Narrowed {
		t.Fatalf("defaults: %+v", cfg)
	}
	if got := cfg.Opts.Scope.End.Format(dayLayout); got != "2026-09-21" || !cfg.Opts.Filter.Until.Equal(cfg.Opts.Scope.End) {
		t.Fatalf("scope end %s, filter until %v", got, cfg.Opts.Filter.Until)
	}

	cfg, _, err = parseVPCArgsFlags([]string{"--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1",
		"--org-id", "o-abc123", "--action", "reject", "--src-cidr", "203.0.113.0/24", "--dst-cidr", "10.0.0.0/8,10.1.2.3",
		"--ports", "22,8000-8100", "--protocol", "tcp,udp", "--interfaces", "eni-1", "--vpcs", "vpc-1",
		"--egress-bytes", "500M", "--scan-ports", "10", "--sweep-hosts", "20", "--emit-flows", "ALL"}, now, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := cfg.Opts.Filter
	if len(f.Actions) != 1 || f.Actions[0] != "REJECT" || len(f.SrcCIDRs) != 1 || len(f.DstCIDRs) != 2 ||
		len(f.Ports) != 2 || f.Ports[1] != (flowlog.PortRange{Lo: 8000, Hi: 8100}) || len(f.Protocols) != 2 ||
		f.Interfaces[0] != "eni-1" || f.VPCs[0] != "vpc-1" || !cfg.Meta.Narrowed {
		t.Fatalf("filter: %+v", f)
	}
	if cfg.Opts.Scope.OrgID != "o-abc123" || cfg.Opts.Rules.EgressBytes != 500<<20 || cfg.Opts.Rules.ScanPorts != 10 ||
		cfg.Opts.Rules.SweepHosts != 20 || cfg.EmitFlows != "all" {
		t.Fatalf("options: %+v / emit %q", cfg.Opts.Rules, cfg.EmitFlows)
	}
}

func TestParseVPCArgsRejectsBadInput(t *testing.T) {
	base := []string{"--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1"}
	for _, bad := range [][]string{
		{"--action", "DROP"}, {"--src-cidr", "nope"}, {"--dst-cidr", "10.0.0.0/33"}, {"--ports", "70000"},
		{"--protocol", "quic"}, {"--emit-flows", "some"}, {"--scan-ports", "0"}, {"--sweep-hosts", "0"},
		{"--egress-bytes", "0"}, {"--egress-bytes", "1.5G"}, {"--fail-on", "bogus"}, {"--max-events", "0"},
	} {
		if _, _, err := parseVPCArgsFlags(append(append([]string{}, base...), bad...), now, nil, nil); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"1GiB": 1 << 30, "1G": 1 << 30, "1gb": 1 << 30, "500M": 500 << 20, "2048": 2048, "4K": 4096, "1T": 1 << 40, "10B": 10} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "-1", "1.5G", "G", "9999999T", "12X"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) accepted", in)
		}
	}
}

func TestRunHelpListsVPC(t *testing.T) {
	var stdout bytes.Buffer
	if code := run(context.Background(), []string{"help"}, &stdout, &bytes.Buffer{}, nil, now); code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stdout.String(), "vpc          scan VPC Flow Logs") || !strings.Contains(stdout.String(), "cloudtrail|elb|waf|s3|vpc") {
		t.Errorf("usage = %s", stdout.String())
	}
}
