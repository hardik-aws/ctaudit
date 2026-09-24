package sink

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsText(t *testing.T) {
	m := NewMetrics()
	m.Gauge("ctaudit_records_read", "Records read.", 42)
	m.GaugeWith("ctaudit_findings", "Findings by severity.", "severity", "low", 1)
	m.GaugeWith("ctaudit_findings", "Findings by severity.", "severity", "critical", 0)
	m.Gauge("ctaudit_scan_duration_seconds", "Scan time.", 1.5)
	want := `# HELP ctaudit_records_read Records read.
# TYPE ctaudit_records_read gauge
ctaudit_records_read 42
# HELP ctaudit_findings Findings by severity.
# TYPE ctaudit_findings gauge
ctaudit_findings{severity="low"} 1
ctaudit_findings{severity="critical"} 0
# HELP ctaudit_scan_duration_seconds Scan time.
# TYPE ctaudit_scan_duration_seconds gauge
ctaudit_scan_duration_seconds 1.5
`
	if got := m.Text(); got != want {
		t.Errorf("Text() =\n%s\nwant\n%s", got, want)
	}
}

func TestPushgatewayPush(t *testing.T) {
	var gotPath, gotType, gotAuth, gotBody, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotType, gotAuth = r.Header.Get("Content-Type"), r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &Pushgateway{URL: srv.URL + "/", Job: "ctaudit", Subcommand: "elb", Auth: Auth{Token: "tok"}}
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
	m := NewMetrics()
	m.Gauge("ctaudit_records_read", "Records read.", 7)
	if err := p.Push(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/metrics/job/ctaudit/subcommand/elb" {
		t.Errorf("%s %s", gotMethod, gotPath)
	}
	if gotType != "text/plain; version=0.0.4" || gotAuth != "Bearer tok" {
		t.Errorf("Content-Type=%q Authorization=%q", gotType, gotAuth)
	}
	if !strings.Contains(gotBody, "ctaudit_records_read 7\n") {
		t.Errorf("body = %q", gotBody)
	}
}

func TestPushgatewayFailure(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "bad metric", http.StatusBadRequest)
	}))
	defer srv.Close()
	p := &Pushgateway{URL: srv.URL, Job: "ctaudit", Subcommand: "cloudtrail", Backoff: time.Millisecond}
	err := p.Push(context.Background(), NewMetrics())
	if err == nil || !strings.Contains(err.Error(), "pushgateway push") || !strings.Contains(err.Error(), "bad metric") {
		t.Errorf("Push = %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestPushgatewayCheck(t *testing.T) {
	if err := (&Pushgateway{URL: "pushgw:9091", Job: "ctaudit"}).Check(); err == nil {
		t.Error("bad URL passed Check")
	}
	if err := (&Pushgateway{URL: "http://pushgw:9091", Job: "a/b"}).Check(); err == nil {
		t.Error("job with a slash passed Check")
	}
}

func TestMetricsCounters(t *testing.T) {
	m := NewMetrics()
	m.Counter("a_total", "A.", 3)
	m.CounterWith("b_total", "B.", "result", "ok", 1)
	m.CounterLabels("c_total", "C.", map[string]string{"subcommand": "elb", "result": "ok"}, 2)
	m.GaugeLabels("d", "D.", map[string]string{"subcommand": "elb"}, 0.5)
	m.GaugeLabels("e", "E.", nil, 7)
	want := `# HELP a_total A.
# TYPE a_total counter
a_total 3
# HELP b_total B.
# TYPE b_total counter
b_total{result="ok"} 1
# HELP c_total C.
# TYPE c_total counter
c_total{result="ok",subcommand="elb"} 2
# HELP d D.
# TYPE d gauge
d{subcommand="elb"} 0.5
# HELP e E.
# TYPE e gauge
e 7
`
	if got := m.Text(); got != want {
		t.Fatalf("text:\n%s\nwant:\n%s", got, want)
	}
}

func TestMetricsLabelsEscaped(t *testing.T) {
	m := NewMetrics()
	m.CounterLabels("x_total", "X.", map[string]string{"v": "a\"b\\c\nd"}, 1)
	if got := m.Text(); !strings.Contains(got, `x_total{v="a\"b\\c\nd"} 1`) {
		t.Fatalf("escaping:\n%s", got)
	}
}
