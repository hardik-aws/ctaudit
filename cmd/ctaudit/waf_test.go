package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

const (
	testWAFKey     = "AWSLogs/111122223333/WAFLogs/us-east-1/prod-acl/2026/09/20/10/00/a.log.gz"
	testWAFTestACL = "AWSLogs/111122223333/WAFLogs/us-east-1/test-acl/2026/09/20/10/00/b.log.gz"

	// wafCleanAllow and wafCleanBlock produce no findings at the default
	// thresholds: one allow, one block, neither an exploit or repeat offender.
	wafCleanAllow = `{"timestamp":1789900000000,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/prod-acl/abcd","terminatingRuleId":"Default_Action","terminatingRuleType":"REGULAR","action":"ALLOW","httpSourceName":"ALB","httpRequest":{"clientIp":"198.51.100.10","country":"US","headers":[{"name":"Host","value":"web.example.com"},{"name":"User-Agent","value":"curl/8.0"}],"uri":"/health","httpMethod":"GET","requestId":"1"}}`
	wafCleanBlock = `{"timestamp":1789900001000,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/prod-acl/abcd","terminatingRuleId":"geo-block","terminatingRuleType":"REGULAR","action":"BLOCK","httpSourceName":"ALB","httpRequest":{"clientIp":"198.51.100.20","country":"NL","headers":[{"name":"Host","value":"web.example.com"},{"name":"User-Agent","value":"curl/8.0"}],"uri":"/admin","httpMethod":"GET","requestId":"2"}}`

	// wafExploitAllow is an ALLOW whose COUNT match is from a managed exploit
	// rule group, the waf-exploit-allowed (CRITICAL) trigger.
	wafExploitAllow = `{"timestamp":1789900002000,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/prod-acl/abcd","terminatingRuleId":"Default_Action","terminatingRuleType":"REGULAR","action":"ALLOW","httpSourceName":"ALB","ruleGroupList":[{"ruleGroupId":"AWS#AWSManagedRulesKnownBadInputsRuleSet","terminatingRule":null,"nonTerminatingMatchingRules":[{"ruleId":"Log4JRCE_HEADER","action":"COUNT"}],"excludedRules":null}],"httpRequest":{"clientIp":"203.0.113.99","country":"US","headers":[{"name":"Host","value":"api.example.com"}],"uri":"/v1/items","httpMethod":"POST","requestId":"3"}}`

	// wafBlockA and wafBlockB block the same IP twice; wafAllowSameIP allows
	// it once with no exploit match, the waf-attacker-allowed (HIGH) trigger.
	wafBlockA      = `{"timestamp":1789900003000,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/prod-acl/abcd","terminatingRuleId":"rule-a","terminatingRuleType":"REGULAR","action":"BLOCK","httpSourceName":"ALB","httpRequest":{"clientIp":"203.0.113.50","country":"US","headers":[],"uri":"/a","httpMethod":"GET","requestId":"4"}}`
	wafBlockB      = `{"timestamp":1789900004000,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/prod-acl/abcd","terminatingRuleId":"rule-a","terminatingRuleType":"REGULAR","action":"BLOCK","httpSourceName":"ALB","httpRequest":{"clientIp":"203.0.113.50","country":"US","headers":[],"uri":"/b","httpMethod":"GET","requestId":"5"}}`
	wafAllowSameIP = `{"timestamp":1789900005000,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/prod-acl/abcd","terminatingRuleId":"Default_Action","terminatingRuleType":"REGULAR","action":"ALLOW","httpSourceName":"ALB","httpRequest":{"clientIp":"203.0.113.50","country":"US","headers":[],"uri":"/c","httpMethod":"GET","requestId":"6"}}`

	// wafProdAllowUS, wafProdBlockNL, and wafProdBlockUS live under prod-acl;
	// wafTestBlockNL lives under test-acl, for the narrowing filter test.
	wafProdAllowUS = `{"timestamp":1789900006000,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/prod-acl/abcd","terminatingRuleId":"Default_Action","terminatingRuleType":"REGULAR","action":"ALLOW","httpSourceName":"ALB","httpRequest":{"clientIp":"198.51.100.30","country":"US","headers":[],"uri":"/p1","httpMethod":"GET","requestId":"7"}}`
	wafProdBlockNL = `{"timestamp":1789900007000,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/prod-acl/abcd","terminatingRuleId":"geo-block","terminatingRuleType":"REGULAR","action":"BLOCK","httpSourceName":"ALB","httpRequest":{"clientIp":"203.0.113.70","country":"NL","headers":[],"uri":"/p2","httpMethod":"GET","requestId":"8"}}`
	wafProdBlockUS = `{"timestamp":1789900008000,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/prod-acl/abcd","terminatingRuleId":"geo-block","terminatingRuleType":"REGULAR","action":"BLOCK","httpSourceName":"ALB","httpRequest":{"clientIp":"198.51.100.31","country":"US","headers":[],"uri":"/p3","httpMethod":"GET","requestId":"9"}}`
	wafTestBlockNL = `{"timestamp":1789900009000,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/test-acl/efgh","terminatingRuleId":"geo-block","terminatingRuleType":"REGULAR","action":"BLOCK","httpSourceName":"ALB","httpRequest":{"clientIp":"203.0.113.71","country":"NL","headers":[],"uri":"/t1","httpMethod":"GET","requestId":"10"}}`
)

// wafStore builds a store serving lines gzipped under testWAFKey.
func wafStore(t *testing.T, lines ...string) storeFactory {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(strings.Join(lines, "\n") + "\n"))
	zw.Close()
	store := s3src.NewMemStore(map[string][]byte{testWAFKey: buf.Bytes()})
	return func(context.Context, storeConfig) (s3src.ObjectStore, error) { return store, nil }
}

func runWAFArgs(t *testing.T, newStore storeFactory, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{
		"waf", "--bucket", "b", "--accounts", "111122223333", "--regions", "us-east-1",
		"--since", "2026-09-20", "--until", "2026-09-20",
	}, extra...)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr, newStore, now)
	return code, stdout.String(), stderr.String()
}

func TestRunWAFCleanDataExitsZero(t *testing.T) {
	code, stdout, stderr := runWAFArgs(t, wafStore(t, wafCleanAllow, wafCleanBlock), "--html", "")
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "AWS WAF Logs") {
		t.Errorf("stdout missing totals line:\n%s", stdout)
	}
	if !strings.Contains(stdout, "FINDINGS (0)") {
		t.Errorf("stdout should report no findings:\n%s", stdout)
	}
}

func TestRunWAFExploitFindingFailsOn(t *testing.T) {
	store := wafStore(t, wafCleanAllow, wafExploitAllow)

	code, stdout, stderr := runWAFArgs(t, store, "--html", "")
	if code != exitFindings {
		t.Fatalf("default --fail-on critical: exit = %d, want %d, stderr = %s", code, exitFindings, stderr)
	}
	if !strings.Contains(stdout, "Exploit payload allowed") || !strings.Contains(stdout, "203.0.113.99") {
		t.Errorf("stdout missing the exploit finding:\n%s", stdout)
	}

	code, _, stderr = runWAFArgs(t, store, "--html", "", "--fail-on", "none")
	if code != exitOK {
		t.Errorf("--fail-on none: exit = %d, want %d, stderr = %s", code, exitOK, stderr)
	}
}

func TestRunWAFAttackerAllowedWithBlockThreshold(t *testing.T) {
	store := wafStore(t, wafBlockA, wafBlockB, wafAllowSameIP)
	code, stdout, stderr := runWAFArgs(t, store, "--html", "", "--fail-on", "high", "--block-threshold", "2")
	if code != exitFindings {
		t.Fatalf("exit = %d, want %d, stderr = %s\nstdout:\n%s", code, exitFindings, stderr, stdout)
	}
	if !strings.Contains(stdout, "Blocked client also allowed") || !strings.Contains(stdout, "203.0.113.50") {
		t.Errorf("stdout missing the attacker-allowed finding:\n%s", stdout)
	}
}

func TestRunWAFExitsTwoOnUnreadableObject(t *testing.T) {
	corrupt := func(context.Context, storeConfig) (s3src.ObjectStore, error) {
		return s3src.NewMemStore(map[string][]byte{testWAFKey: []byte("not gzip")}), nil
	}
	if code, stdout, _ := runWAFArgs(t, corrupt, "--html", ""); code != exitFailed || !strings.Contains(stdout, "ERRORS (1)") {
		t.Errorf("unreadable object: exit = %d, want %d with the error listed\n%s", code, exitFailed, stdout)
	}
}

func TestRunWAFWritesHTMLAndPDF(t *testing.T) {
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "w.html")
	pdfPath := filepath.Join(dir, "w.pdf")
	code, stdout, stderr := runWAFArgs(t, wafStore(t, wafCleanAllow, wafCleanBlock), "--html", htmlPath, "--pdf", pdfPath)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "HTML report written to "+htmlPath) || !strings.Contains(stdout, "PDF report written to "+pdfPath) {
		t.Errorf("stdout missing report notes:\n%s", stdout)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	if strings.Contains(string(html), "<link") {
		t.Errorf("html report must be self-contained, found <link")
	}
	pdf, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("read pdf: %v", err)
	}
	if !strings.HasPrefix(string(pdf), "%PDF-") {
		t.Errorf("pdf report does not start with %%PDF-")
	}
}

func TestRunWAFJSONLIsUncapped(t *testing.T) {
	dir := t.TempDir()
	jsonl := filepath.Join(dir, "w.jsonl")
	store := wafStore(t, wafCleanAllow, wafExploitAllow)
	code, _, stderr := runWAFArgs(t, store, "--html", "", "--fail-on", "none", "--jsonl", jsonl)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	lines := readJSONL(t, jsonl)
	kinds := map[string]int{}
	for _, l := range lines {
		kinds[l["kind"].(string)]++
	}
	if kinds["request"] != 2 {
		t.Errorf("kinds[request] = %d, want 2 (one per matching request)", kinds["request"])
	}
	if kinds["finding"] < 1 {
		t.Errorf("kinds[finding] = %d, want at least 1", kinds["finding"])
	}
}

// wafTwoACLStore puts the prod-acl lines and the test-acl line under separate
// object keys, since the web ACL name comes from the S3 key path, not the
// JSON body, and is used to select which prefixes are even scanned.
func wafTwoACLStore(t *testing.T, prodLines []string, testLine string) storeFactory {
	t.Helper()
	gz := func(lines ...string) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write([]byte(strings.Join(lines, "\n") + "\n"))
		zw.Close()
		return buf.Bytes()
	}
	store := s3src.NewMemStore(map[string][]byte{
		testWAFKey:     gz(prodLines...),
		testWAFTestACL: gz(testLine),
	})
	return func(context.Context, storeConfig) (s3src.ObjectStore, error) { return store, nil }
}

func TestRunWAFNarrowsMatches(t *testing.T) {
	store := wafTwoACLStore(t, []string{wafProdAllowUS, wafProdBlockNL, wafProdBlockUS}, wafTestBlockNL)

	code, stdout, stderr := runWAFArgs(t, store, "--html", "")
	if code != exitOK {
		t.Fatalf("unfiltered: exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "Matched: 4") {
		t.Errorf("unfiltered stdout should match all 4 records:\n%s", stdout)
	}

	code, stdout, stderr = runWAFArgs(t, store, "--html", "", "--action", "block", "--web-acls", "prod", "--country", "NL")
	if code != exitOK {
		t.Fatalf("filtered: exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "Matched: 1") {
		t.Errorf("filtered stdout should match only 1 record:\n%s", stdout)
	}
}

func TestRunWAFBadActionFlagExitsTwo(t *testing.T) {
	code, _, stderr := runWAFArgs(t, wafStore(t, wafCleanAllow), "--action", "nope")
	if code != exitFailed {
		t.Fatalf("exit = %d, want %d", code, exitFailed)
	}
	for _, want := range []string{"ALLOW", "BLOCK", "COUNT", "CAPTCHA", "CHALLENGE"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing valid action %q: %s", want, stderr)
		}
	}
}

func TestRunHelpListsWAF(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-h"}, &stdout, &stderr, wafStore(t, wafCleanAllow), now); code != exitOK {
		t.Errorf("-h: exit = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "waf") {
		t.Errorf("top-level usage should list waf:\n%s", stdout.String())
	}
}

func TestParseWAFArgs(t *testing.T) {
	cfg, err := parseWAFArgs(baseArgs(), now)
	if err != nil {
		t.Fatalf("parseWAFArgs: %v", err)
	}
	if cfg.HTMLPath != "waf-report.html" || cfg.PDFPath != "" || cfg.TopN != 10 || cfg.Opts.MaxEvents != 200 {
		t.Errorf("defaults: HTMLPath=%q PDFPath=%q TopN=%d MaxEvents=%d", cfg.HTMLPath, cfg.PDFPath, cfg.TopN, cfg.Opts.MaxEvents)
	}
	if cfg.FailOff {
		t.Errorf("FailOff should default to false")
	}
	if cfg.Opts.BlockThreshold != 100 {
		t.Errorf("BlockThreshold = %d, want 100", cfg.Opts.BlockThreshold)
	}
	if cfg.Meta.Narrowed {
		t.Errorf("Narrowed should be false with no filters")
	}

	cfg, err = parseWAFArgs(baseArgs(
		"--web-acls", "prod, test", "--action", "block,Allow", "--client-ip", "10.0.",
		"--country", "nl,us", "--rule", "sqli", "--uri", "/login", "--host", "example.com",
		"--block-threshold", "5", "--fail-on", "high",
	), now)
	if err != nil {
		t.Fatalf("parseWAFArgs with filters: %v", err)
	}
	f := cfg.Opts.Filter
	if len(cfg.Opts.WebACLs) != 2 || cfg.Opts.WebACLs[1] != "test" {
		t.Errorf("WebACLs = %q", cfg.Opts.WebACLs)
	}
	if len(f.Actions) != 2 || f.Actions[0] != "BLOCK" || f.Actions[1] != "ALLOW" {
		t.Errorf("Actions = %q, want upper-cased", f.Actions)
	}
	if f.ClientIP != "10.0." || f.Rule != "sqli" || f.URI != "/login" || f.Host != "example.com" {
		t.Errorf("substring filters = %+v", f)
	}
	if len(f.Countries) != 2 || f.Countries[1] != "us" {
		t.Errorf("Countries = %q", f.Countries)
	}
	if cfg.Opts.BlockThreshold != 5 {
		t.Errorf("BlockThreshold = %d, want 5", cfg.Opts.BlockThreshold)
	}
	if cfg.FailOff || cfg.FailOn.String() != "HIGH" {
		t.Errorf("FailOn = %v FailOff=%v, want HIGH and false", cfg.FailOn, cfg.FailOff)
	}
	if !cfg.Meta.Narrowed {
		t.Errorf("Narrowed should be true with filters")
	}

	cfg, err = parseWAFArgs(baseArgs("--fail-on", "none"), now)
	if err != nil || !cfg.FailOff {
		t.Errorf("--fail-on none: err=%v FailOff=%v, want true", err, cfg.FailOff)
	}
}

func TestParseWAFArgsRejectsBadInput(t *testing.T) {
	cases := map[string][]string{
		"missing bucket":        {"--accounts", "111122223333", "--regions", "us-east-1"},
		"bad account":           {"--bucket", "b", "--accounts", "12", "--regions", "us-east-1"},
		"bad action":            baseArgs("--action", "nope"),
		"bad fail-on":           baseArgs("--fail-on", "urgent"),
		"bad block-threshold":   baseArgs("--block-threshold", "0"),
		"negative block-thresh": baseArgs("--block-threshold", "-1"),
		"bad max-events":        baseArgs("--max-events", "0"),
		"txt report":            baseArgs("--html", "r.txt"),
		"txt pdf":               baseArgs("--pdf", "r.txt"),
		"stray argument":        baseArgs("extra"),
	}
	for name, args := range cases {
		if _, err := parseWAFArgs(args, now); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
