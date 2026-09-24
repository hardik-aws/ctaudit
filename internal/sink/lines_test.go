package sink

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/findings"
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
	labels, line := enc.Event(r)
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
	_, line := enc.Event(r)
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
	labels, _ := enc.Event(ctevent.Record{})
	if _, ok := labels["account"]; ok {
		t.Errorf("labels = %v, want no empty account", labels)
	}
}

func TestEncoderFinding(t *testing.T) {
	f := findings.Finding{
		Rule: "root-usage", Severity: findings.SevCritical, Title: "Root used",
		Account: "111122223333", Time: time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC),
	}
	labels, line := enc.Finding(f)
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
	labels, line := e.ELB(x)
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
	labels, line = e.ELB(x)
	if labels["kind"] != "conn" || decode(t, line)["kind"] != "conn" {
		t.Errorf("connection row: labels=%v line=%s", labels, line)
	}
}
