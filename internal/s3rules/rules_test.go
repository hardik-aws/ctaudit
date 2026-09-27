package s3rules

import (
	"strings"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

var t0 = time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)

func only(t *testing.T, fs []findings.Finding, rule string) []findings.Finding {
	t.Helper()
	var out []findings.Finding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func TestAnonymousWriteAndRead(t *testing.T) {
	s := stats.NewS3Summary()
	s.AnonWrites["data"] = &stats.S3AnonHit{Count: 2, First: t0, IPs: stats.Counter{"192.0.2.44": 2},
		Keys: stats.Counter{"uploads/shell.php": 2}, Ops: stats.Counter{"REST.PUT.OBJECT": 2}}
	s.AnonReads["web"] = &stats.S3AnonHit{Count: 9, First: t0, IPs: stats.Counter{"203.0.113.9": 9},
		Keys: stats.Counter{"img/logo.png": 9}, Ops: stats.Counter{"REST.GET.OBJECT": 9}}
	fs, _ := Detect(s, Options{})
	w := only(t, fs, "s3-anonymous-write")
	if len(w) != 1 || w[0].Severity != findings.SevCritical || w[0].Actor != "data" || !w[0].Time.Equal(t0) ||
		!strings.Contains(w[0].Detail, "192.0.2.44") || !strings.Contains(w[0].Detail, "uploads/shell.php") {
		t.Fatalf("anonymous write: %+v", w)
	}
	r := only(t, fs, "s3-anonymous-read")
	if len(r) != 1 || r[0].Severity != findings.SevHigh || r[0].Actor != "web" || !strings.Contains(r[0].Detail, "9 ") {
		t.Fatalf("anonymous read: %+v", r)
	}
	if fs[0].Rule != "s3-anonymous-write" {
		t.Fatalf("CRITICAL must sort first: %+v", fs[0])
	}
}

func TestDeniedBurst(t *testing.T) {
	s := stats.NewS3Summary()
	s.DeniedByIP = stats.Counter{"192.0.2.50": 5, "192.0.2.51": 4, stats.S3Other: 99}
	s.DeniedByRequester = stats.Counter{"arn:aws:sts::444455556666:assumed-role/scanner/i-0abc": 5}
	fs, _ := Detect(s, Options{DeniedThreshold: 5})
	d := only(t, fs, "s3-access-denied-burst")
	if len(d) != 2 || d[0].Severity != findings.SevHigh {
		t.Fatalf("denied: %+v", d)
	}
	for _, f := range d {
		if f.Actor == stats.S3Other || f.Actor == "192.0.2.51" {
			t.Fatalf("unexpected actor %q", f.Actor)
		}
	}
	if fs, _ := Detect(s, Options{}); len(only(t, fs, "s3-access-denied-burst")) != 0 {
		t.Fatal("default threshold 100 must not fire at 5")
	}
}

func TestMassDelete(t *testing.T) {
	s := stats.NewS3Summary()
	s.DeletesByPrincipal = stats.Counter{"alice": 1000, "bob": 999}
	fs, _ := Detect(s, Options{})
	d := only(t, fs, "s3-mass-delete")
	if len(d) != 1 || d[0].Actor != "alice" || d[0].Severity != findings.SevHigh || !strings.Contains(d[0].Detail, "1000") {
		t.Fatalf("mass delete: %+v", d)
	}
}

func TestAccessChange(t *testing.T) {
	s := stats.NewS3Summary()
	s.AccessChanges = []stats.S3AccessChange{
		{Time: t0, Bucket: "data", Operation: "REST.PUT.BUCKETPOLICY", Principal: "alice", RemoteIP: "198.51.100.7"},
		{Time: t0.Add(time.Minute), Bucket: "data", Operation: "REST.PUT.ACL", Key: "public.txt", Principal: "alice", RemoteIP: "198.51.100.7"},
	}
	fs, _ := Detect(s, Options{})
	c := only(t, fs, "s3-access-change")
	if len(c) != 2 || c[0].Severity != findings.SevMedium || !c[0].Time.Equal(t0) || !strings.Contains(c[0].Detail, "REST.PUT.BUCKETPOLICY") ||
		!strings.Contains(c[1].Detail, "public.txt") {
		t.Fatalf("access change: %+v", c)
	}
}

func TestLargeEgress(t *testing.T) {
	s := stats.NewS3Summary()
	s.BytesByRequester = stats.Counter{"alice": 2048, "bob": 10}
	s.BytesByIP = stats.Counter{"203.0.113.9": 4096, stats.S3Other: 1 << 40}
	fs, _ := Detect(s, Options{EgressBytes: 2048})
	e := only(t, fs, "s3-large-egress")
	if len(e) != 2 || e[0].Severity != findings.SevMedium {
		t.Fatalf("egress: %+v", e)
	}
	if e[0].Actor != "203.0.113.9" || e[1].Actor != "alice" {
		t.Fatalf("egress order: %q %q", e[0].Actor, e[1].Actor)
	}
}

func TestPostureRules(t *testing.T) {
	s := stats.NewS3Summary()
	s.WeakTLSBy = stats.Counter{"legacy": 3}
	s.PlainHTTPBy = stats.Counter{"anonymous": 2}
	s.SigV2By = stats.Counter{"legacy": 1, stats.S3Other: 7}
	fs, _ := Detect(s, Options{})
	for rule, actor := range map[string]string{"s3-weak-tls": "legacy", "s3-plain-http": "anonymous", "s3-sigv2": "legacy"} {
		got := only(t, fs, rule)
		if len(got) != 1 || got[0].Severity != findings.SevLow || got[0].Actor != actor {
			t.Errorf("%s: %+v", rule, got)
		}
	}
}

func TestCapKeepsCritical(t *testing.T) {
	s := stats.NewS3Summary()
	for _, b := range []string{"a", "b", "c"} {
		s.AnonWrites[b] = &stats.S3AnonHit{Count: 1, IPs: stats.Counter{}, Keys: stats.Counter{}, Ops: stats.Counter{}}
	}
	s.WeakTLSBy = stats.Counter{"p1": 1, "p2": 1, "p3": 1, "p4": 1, "p5": 1}
	fs, dropped := Detect(s, Options{Max: 2})
	if len(fs) != 3 || dropped != 5 {
		t.Fatalf("got %d findings, dropped %d", len(fs), dropped)
	}
	for _, f := range fs {
		if f.Severity != findings.SevCritical {
			t.Fatalf("non-critical kept past the cap: %+v", f)
		}
	}
	if sev, ok := MaxSeverity(fs); !ok || sev != findings.SevCritical {
		t.Fatalf("MaxSeverity = %v %v", sev, ok)
	}
	if _, ok := MaxSeverity(nil); ok {
		t.Fatal("MaxSeverity(nil) must report false")
	}
}
