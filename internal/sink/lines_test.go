package sink

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/s3log"
	"github.com/gsmappdev/ctaudit/internal/waflog"
)

var enc = Encoder{Job: "ctaudit", Subcommand: "cloudtrail", RunID: "run-1"}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("line is not JSON: %v: %s", err, b)
	}
	return m
}

func TestEncoderEvent(t *testing.T) {
	r := ctevent.Record{
		EventName: "DeleteBucket", AWSRegion: "us-east-1", RecipientAccountID: "111122223333",
		EventTime:         time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		RequestParameters: json.RawMessage(`{"bucketName":"b"}`),
	}
	labels, _, line := enc.Event(r)
	want := Labels{"job": "ctaudit", "subcommand": "cloudtrail", "kind": "event", "account": "111122223333", "region": "us-east-1"}
	if labels.key() != want.key() {
		t.Errorf("labels = %v, want %v", labels, want)
	}
	m := decode(t, line)
	if m["kind"] != "event" || m["run_id"] != "run-1" || m["eventName"] != "DeleteBucket" || m["eventTime"] != "2026-09-01T00:00:00Z" {
		t.Errorf("line = %s", line)
	}
	if _, ok := m["truncated"]; ok {
		t.Error("small line is marked truncated")
	}
}

func TestEncoderEventTruncates(t *testing.T) {
	big := `{"x":"` + strings.Repeat("a", maxEventLine) + `"}`
	r := ctevent.Record{EventName: "PutObject", RequestParameters: json.RawMessage(big)}
	_, _, line := enc.Event(r)
	if len(line) > maxEventLine {
		t.Errorf("line is %d bytes, want at most %d", len(line), maxEventLine)
	}
	m := decode(t, line)
	if m["truncated"] != true || m["eventName"] != "PutObject" {
		t.Errorf("line = %s", line)
	}
	if m["requestParameters"] != nil {
		t.Error("truncated line still has requestParameters")
	}
}

func TestEncoderEventOmitsEmptyLabels(t *testing.T) {
	labels, _, _ := enc.Event(ctevent.Record{})
	if _, ok := labels["account"]; ok {
		t.Errorf("labels = %v, want no empty account", labels)
	}
}

func TestEncoderFinding(t *testing.T) {
	f := findings.Finding{
		Rule: "root-usage", Severity: findings.SevCritical, Title: "Root used",
		Account: "111122223333", Time: time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC),
	}
	labels, _, line := enc.Finding(f)
	if labels["severity"] != "critical" || labels["kind"] != "finding" || labels["account"] != "111122223333" {
		t.Errorf("labels = %v", labels)
	}
	m := decode(t, line)
	if m["rule"] != "root-usage" || m["severity"] != "critical" || m["event_time"] != "2026-09-01T01:00:00Z" {
		t.Errorf("line = %s", line)
	}
}

func TestEncoderELB(t *testing.T) {
	e := Encoder{Job: "ctaudit", Subcommand: "elb", RunID: "run-2"}
	x := elblog.Entry{
		Kind: elblog.ALB, LB: "app/web/abc", ClientIP: "1.2.3.4", ELBStatus: "502",
		RequestTime: 0.001, TargetTime: -1, ResponseTime: -1, Latency: -1, TLSHandshakeTime: -1,
		UserAgent: "curl/8", Time: time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC),
	}
	labels, _, line := e.ELB(x)
	if labels["kind"] != "request" || labels["lb"] != "app/web/abc" || labels["subcommand"] != "elb" {
		t.Errorf("labels = %v", labels)
	}
	if _, ok := labels["client_ip"]; ok {
		t.Error("client IP became a label")
	}
	m := decode(t, line)
	if m["kind"] != "request" || m["lb_type"] != "alb" || m["client_ip"] != "1.2.3.4" || m["elb_status"] != "502" {
		t.Errorf("line = %s", line)
	}
	if m["request_time"] != 0.001 {
		t.Errorf("request_time = %v", m["request_time"])
	}
	for _, k := range []string{"target_time", "latency", "tls_handshake_time"} {
		if _, ok := m[k]; ok {
			t.Errorf("unknown %s is in the line", k)
		}
	}

	x.Conn = true
	labels, _, line = e.ELB(x)
	if labels["kind"] != "conn" || decode(t, line)["kind"] != "conn" {
		t.Errorf("connection row: labels=%v line=%s", labels, line)
	}
}

func TestEncoderWAF(t *testing.T) {
	e := Encoder{Job: "ctaudit", Subcommand: "waf", RunID: "run-3"}
	x := waflog.Entry{
		WebACL: "prod-acl", Action: "BLOCK",
		Rule: "rule-123", RuleType: "MANAGED", RuleGroup: "AWSManagedRulesSQLiRuleSet",
		Source: "CLOUDFRONT", SourceID: "dist-abc",
		ClientIP: "1.2.3.4", Country: "US", Method: "POST", Host: "example.com",
		URI: "/api/login", UserAgent: "curl/8",
		Labels: []string{"label1"}, CountRules: []string{"rule-456"}, RateRule: "rate-123",
		ResponseCode: 403, Oversize: true, JA3: "ja3-abc", JA4: "ja4-abc",
		RequestID: "req-123", ChallengeFailed: true,
		Time: time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC),
	}
	labels, retTime, line := e.WAF(x)

	// Check labels
	want := Labels{
		"job": "ctaudit", "subcommand": "waf", "kind": "request",
		"acl": "prod-acl", "action": "BLOCK",
	}
	if labels.key() != want.key() {
		t.Errorf("labels = %v, want %v", labels, want)
	}

	// Check returned time
	if retTime != x.Time {
		t.Errorf("returned time = %v, want %v", retTime, x.Time)
	}

	// Check JSON decodes correctly
	m := decode(t, line)

	// Required keys
	if m["kind"] != "request" || m["run_id"] != "run-3" || m["event_time"] != "2026-09-01T03:00:00Z" || m["action"] != "BLOCK" {
		t.Errorf("missing or wrong required key: line = %s", line)
	}

	// Optional keys that should be present
	requiredKeys := []string{"web_acl", "rule", "rule_type", "rule_group", "source", "source_id",
		"client_ip", "country", "method", "host", "uri", "user_agent", "labels", "count_rules",
		"rate_rule", "response_code", "oversize", "ja3", "ja4", "request_id", "challenge_failed"}
	for _, k := range requiredKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("key %s missing from line: %s", k, line)
		}
	}
}

func TestEncoderWAFOmitsEmptyFields(t *testing.T) {
	e := Encoder{Job: "ctaudit", Subcommand: "waf", RunID: "run-4"}
	x := waflog.Entry{
		WebACL: "prod-acl", Action: "ALLOW",
		Time: time.Date(2026, 9, 1, 4, 0, 0, 0, time.UTC),
	}
	_, _, line := e.WAF(x)
	m := decode(t, line)

	// Required fields should always be present
	if m["kind"] != "request" || m["run_id"] != "run-4" || m["action"] != "ALLOW" {
		t.Errorf("required field missing: %s", line)
	}

	// Optional fields should be omitted when empty
	emptyFields := []string{"rule", "rule_type", "rule_group", "source", "source_id",
		"client_ip", "country", "method", "host", "uri", "user_agent", "labels", "count_rules",
		"rate_rule", "ja3", "ja4", "request_id"}
	for _, k := range emptyFields {
		if _, ok := m[k]; ok {
			t.Errorf("empty field %s should be omitted but is present: %s", k, line)
		}
	}
}

func TestEncoderS3(t *testing.T) {
	x := s3log.Entry{
		Time: time.Date(2026, 9, 20, 10, 15, 2, 0, time.UTC), Bucket: "data-bucket", RemoteIP: "192.0.2.50",
		Requester: "arn:aws:iam::111122223333:user/alice", RequestID: "6D7E", Operation: "REST.GET.OBJECT",
		Key: "secrets/db.env", Method: "GET", Path: "/secrets/db.env", Proto: "HTTP/1.1", Status: 403,
		ErrorCode: "AccessDenied", BytesSent: 243, TotalTimeMS: 9, TurnaroundMS: -1, UserAgent: "Boto3/1.34.0",
		SigVersion: "SigV4", CipherSuite: "ECDHE-RSA-AES128-GCM-SHA256", AuthType: "AuthHeader",
		HostHeader: "data-bucket.s3.us-east-1.amazonaws.com", TLSVersion: "TLSv1.2",
	}
	enc := Encoder{Job: "ctaudit", Subcommand: "s3", RunID: "r1"}
	labels, at, line := enc.S3(x)
	want := Labels{"job": "ctaudit", "subcommand": "s3", "kind": "request", "bucket": "data-bucket", "status_class": "4xx"}
	if !reflect.DeepEqual(labels, want) || !at.Equal(x.Time) {
		t.Fatalf("labels %v at %v", labels, at)
	}
	var got map[string]any
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]any{
		"kind": "request", "run_id": "r1", "bucket": "data-bucket", "remote_ip": "192.0.2.50",
		"requester": "arn:aws:iam::111122223333:user/alice", "operation": "REST.GET.OBJECT", "key": "secrets/db.env",
		"method": "GET", "path": "/secrets/db.env", "status": float64(403), "error_code": "AccessDenied",
		"bytes_sent": float64(243), "total_time_ms": float64(9), "tls_version": "TLSv1.2", "auth_type": "AuthHeader",
	} {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if _, ok := got["turnaround_time_ms"]; ok {
		t.Error("unknown turnaround time must be omitted")
	}
	if _, ok := got["event_time"]; !ok {
		t.Error("event_time missing")
	}
}

func TestEncoderS3Anonymous(t *testing.T) {
	_, _, line := Encoder{Subcommand: "s3"}.S3(s3log.Entry{Bucket: "b", Operation: "REST.PUT.OBJECT", TotalTimeMS: -1, TurnaroundMS: -1})
	var got map[string]any
	json.Unmarshal(line, &got)
	if got["requester"] != "anonymous" || got["bytes_sent"] != float64(0) {
		t.Fatalf("line = %s", line)
	}
	for _, k := range []string{"key", "status", "referer", "plain_http", "acl_required"} {
		if _, ok := got[k]; ok {
			t.Errorf("empty %s must be omitted: %s", k, line)
		}
	}
}
