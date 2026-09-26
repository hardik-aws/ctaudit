package waflog

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"
)

const blockManaged = `{"timestamp":1789900000123,"formatVersion":1,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/prod-acl/abcd","terminatingRuleId":"AWS-AWSManagedRulesSQLiRuleSet","terminatingRuleType":"MANAGED_RULE_GROUP","action":"BLOCK","httpSourceName":"ALB","httpSourceId":"111122223333-app/web/abc","ruleGroupList":[{"ruleGroupId":"AWS#AWSManagedRulesSQLiRuleSet","terminatingRule":{"ruleId":"SQLi_QUERYARGUMENTS","action":"BLOCK"},"nonTerminatingMatchingRules":[],"excludedRules":null}],"rateBasedRuleList":[],"nonTerminatingMatchingRules":[],"responseCodeSent":403,"httpRequest":{"clientIp":"203.0.113.9","country":"NL","headers":[{"name":"Host","value":"web.example.com"},{"name":"User-Agent","value":"sqlmap/1.7"},{"name":"Cookie","value":"session=SECRET"},{"name":"Authorization","value":"Bearer SECRET"}],"uri":"/login","args":"id=1%27%20OR%201=1&token=SECRET","httpVersion":"HTTP/1.1","httpMethod":"GET","requestId":"1-abc"},"labels":[{"name":"awswaf:managed:aws:sql-database:SQLi_QueryArguments"}],"ja3Fingerprint":"j3","ja4Fingerprint":"j4"}`

const allowCounted = `{"timestamp":1789900001000,"webaclId":"arn:aws:wafv2:us-east-1:111122223333:regional/webacl/prod-acl/abcd","terminatingRuleId":"Default_Action","terminatingRuleType":"REGULAR","action":"ALLOW","httpSourceName":"ALB","httpSourceId":"x","ruleGroupList":[{"ruleGroupId":"AWS#AWSManagedRulesKnownBadInputsRuleSet","terminatingRule":null,"nonTerminatingMatchingRules":[{"ruleId":"Log4JRCE_HEADER","action":"COUNT"}],"excludedRules":[{"exclusionType":"EXCLUDED_AS_COUNT","ruleId":"JavaDeserializationRCE_BODY"}]}],"nonTerminatingMatchingRules":[{"ruleId":"geo-watch","action":"COUNT"},{"ruleId":"captcha-soft","action":"CAPTCHA"}],"httpRequest":{"clientIp":"198.51.100.7","country":"US","headers":[{"name":"host","value":"api.example.com"}],"uri":"/v1/items","httpMethod":"POST","requestId":"2-def"},"labels":[{"name":"awswaf:managed:aws:known-bad-inputs:Log4JRCE_Header"}],"oversizeFields":["REQUEST_BODY"]}`

const rateBased = `{"timestamp":1789900002000,"webaclId":"arn:aws:wafv2:us-east-1:1:global/webacl/cf-acl/x","terminatingRuleId":"rate-limit-ip","terminatingRuleType":"RATE_BASED","action":"BLOCK","httpSourceName":"CF","httpSourceId":"E123","httpRequest":{"clientIp":"192.0.2.1","country":"CN","headers":[],"uri":"/","httpMethod":"GET","requestId":"3"}}`

const captchaFail = `{"timestamp":1789900003000,"webaclId":"arn:aws:wafv2:us-east-1:1:regional/webacl/prod-acl/abcd","terminatingRuleId":"bot-captcha","terminatingRuleType":"REGULAR","action":"CAPTCHA","httpSourceName":"ALB","httpRequest":{"clientIp":"192.0.2.2","country":"BR","headers":[],"uri":"/signup","httpMethod":"GET","requestId":"4"},"captchaResponse":{"responseCode":405,"failureReason":"TOKEN_MISSING"}}`

func TestParseManagedBlock(t *testing.T) {
	e, err := Parse([]byte(blockManaged))
	if err != nil {
		t.Fatal(err)
	}
	if !e.Time.Equal(time.UnixMilli(1789900000123).UTC()) || e.WebACL != "prod-acl" || e.Action != "BLOCK" {
		t.Fatalf("basic fields: %+v", e)
	}
	if e.Rule != "AWSManagedRulesSQLiRuleSet/SQLi_QUERYARGUMENTS" || e.RuleGroup != "AWSManagedRulesSQLiRuleSet" || e.RuleType != "MANAGED_RULE_GROUP" {
		t.Fatalf("rule: %q group %q type %q", e.Rule, e.RuleGroup, e.RuleType)
	}
	if e.Host != "web.example.com" || e.UserAgent != "sqlmap/1.7" || e.ClientIP != "203.0.113.9" || e.Country != "NL" ||
		e.Method != "GET" || e.URI != "/login" || e.ResponseCode != 403 || e.JA3 != "j3" || e.JA4 != "j4" || e.RequestID != "1-abc" {
		t.Fatalf("request fields: %+v", e)
	}
	if len(e.Labels) != 1 || e.Source != "ALB" {
		t.Fatalf("labels/source: %+v", e)
	}
}

func TestParseDropsSecrets(t *testing.T) {
	e, _ := Parse([]byte(blockManaged))
	if s := strings.ToLower(fmtEntry(e)); strings.Contains(s, "secret") || strings.Contains(s, "or 1=1") {
		t.Fatalf("entry leaks dropped data: %s", s)
	}
}

func TestParseCountsAndExploit(t *testing.T) {
	e, err := Parse([]byte(allowCounted))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"AWSManagedRulesKnownBadInputsRuleSet/Log4JRCE_HEADER", "AWSManagedRulesKnownBadInputsRuleSet/JavaDeserializationRCE_BODY", "geo-watch"}
	if strings.Join(e.CountRules, ",") != strings.Join(want, ",") {
		t.Fatalf("CountRules = %v", e.CountRules)
	}
	if e.Rule != "Default_Action" || e.RuleGroup != "" || !e.Oversize || e.Host != "api.example.com" {
		t.Fatalf("fields: %+v", e)
	}
	if e.ExploitMatch() == "" {
		t.Fatal("ALLOW with KnownBadInputs COUNT match must be an exploit match")
	}
	b, _ := Parse([]byte(blockManaged))
	if b.ExploitMatch() != "" {
		t.Fatal("a BLOCK is never an allowed exploit")
	}
}

func TestParseRateAndCaptcha(t *testing.T) {
	r, _ := Parse([]byte(rateBased))
	if r.RateRule != "rate-limit-ip" || r.WebACL != "cf-acl" || r.Source != "CF" {
		t.Fatalf("rate: %+v", r)
	}
	c, _ := Parse([]byte(captchaFail))
	if !c.ChallengeFailed || c.Action != "CAPTCHA" {
		t.Fatalf("captcha: %+v", c)
	}
}

func TestDecodeGzipAndBadLine(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(blockManaged + "\n{not json\n\n" + rateBased + "\n"))
	zw.Close()
	got, err := Decode("AWSLogs/1/WAFLogs/us-east-1/prod-acl/2026/09/20/10/00/x.log.gz", &buf)
	le, ok := err.(*LineError)
	if !ok || le.Bad != 1 || len(got) != 2 {
		t.Fatalf("got %d entries, err %v", len(got), err)
	}
}

func TestIsLogKey(t *testing.T) {
	for key, want := range map[string]bool{
		"AWSLogs/1/WAFLogs/us-east-1/a/2026/09/20/10/00/x.log.gz": true,
		"AWSLogs/1/WAFLogs/us-east-1/a/2026/09/20/10/00/x.gz":     true,
		"AWSLogs/1/WAFLogs/us-east-1/a/":                          false,
		"AWSLogs/1/WAFLogs/us-east-1/a/readme.txt":                false,
	} {
		if IsLogKey(key) != want {
			t.Errorf("IsLogKey(%q) != %v", key, want)
		}
	}
}

func fmtEntry(e Entry) string {
	return strings.Join(append(append([]string{e.Host, e.UserAgent, e.URI}, e.Labels...), e.CountRules...), " ")
}
