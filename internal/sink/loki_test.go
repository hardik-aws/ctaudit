package sink

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type pushBody struct {
	Streams []struct {
		Stream map[string]string `json:"stream"`
		Values [][2]string       `json:"values"`
	} `json:"streams"`
}

type fakeLoki struct {
	mu      sync.Mutex
	bodies  []pushBody
	headers []http.Header
	paths   []string
	status  func(n int) int
	calls   atomic.Int32
}

func (f *fakeLoki) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := int(f.calls.Add(1))
	if f.status != nil {
		if code := f.status(n); code != http.StatusNoContent {
			http.Error(w, "nope", code)
			return
		}
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	raw, _ := io.ReadAll(zr)
	var b pushBody
	if err := json.Unmarshal(raw, &b); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	f.mu.Lock()
	f.bodies = append(f.bodies, b)
	f.headers = append(f.headers, r.Header.Clone())
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func newTestLoki(t *testing.T, f *fakeLoki, cfg LokiConfig) *Loki {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cfg.URL = srv.URL + "/"
	cfg.Backoff = time.Millisecond
	l, err := NewLoki(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLokiPushBody(t *testing.T) {
	f := &fakeLoki{}
	start := time.Unix(1_700_000_000, 0)
	l := newTestLoki(t, f, LokiConfig{Start: start})
	w := l.NewWriter()
	ev := Labels{"job": "ctaudit", "kind": "event"}
	fi := Labels{"job": "ctaudit", "kind": "finding"}
	w.Write(ev, []byte(`{"a":1}`))
	w.Write(fi, []byte(`{"b":2}`))
	w.Write(ev, []byte(`{"a":3}`))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	if len(f.bodies) != 1 {
		t.Fatalf("got %d pushes, want 1", len(f.bodies))
	}
	if f.paths[0] != "/loki/api/v1/push" {
		t.Errorf("path = %q", f.paths[0])
	}
	h := f.headers[0]
	if h.Get("Content-Encoding") != "gzip" || h.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v", h)
	}
	if h.Get("X-Scope-OrgID") != "" || h.Get("Authorization") != "" {
		t.Errorf("unexpected tenant or auth header: %v", h)
	}
	streams := f.bodies[0].Streams
	if len(streams) != 2 {
		t.Fatalf("got %d streams, want 2", len(streams))
	}
	if streams[0].Stream["kind"] != "event" || len(streams[0].Values) != 2 {
		t.Errorf("first stream = %+v", streams[0])
	}
	if streams[1].Stream["kind"] != "finding" || streams[1].Values[0][1] != `{"b":2}` {
		t.Errorf("second stream = %+v", streams[1])
	}
	seen := map[string]bool{}
	for _, s := range streams {
		for _, v := range s.Values {
			if seen[v[0]] {
				t.Errorf("duplicate timestamp %s", v[0])
			}
			seen[v[0]] = true
			if !strings.HasPrefix(v[0], "17000000000000000") {
				t.Errorf("timestamp %s is not near Start", v[0])
			}
		}
	}
}

func TestLokiBatchesAtLineLimit(t *testing.T) {
	f := &fakeLoki{}
	l := newTestLoki(t, f, LokiConfig{BatchLines: 2})
	w := l.NewWriter()
	for range 5 {
		w.Write(Labels{"k": "v"}, []byte("x"))
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, b := range f.bodies {
		for _, s := range b.Streams {
			total += len(s.Values)
		}
	}
	if len(f.bodies) != 3 || total != 5 {
		t.Errorf("got %d pushes with %d lines, want 3 with 5", len(f.bodies), total)
	}
}

func TestLokiAuthHeaders(t *testing.T) {
	tests := []struct {
		name   string
		cfg    LokiConfig
		header string
		want   string
	}{
		{"tenant", LokiConfig{Tenant: "team-a"}, "X-Scope-OrgID", "team-a"},
		{"basic", LokiConfig{Auth: Auth{User: "u", Password: "p"}}, "Authorization", "Basic dTpw"},
		{"bearer", LokiConfig{Auth: Auth{Token: "tok"}}, "Authorization", "Bearer tok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeLoki{}
			l := newTestLoki(t, f, tt.cfg)
			l.NewWriter().Write(Labels{"k": "v"}, []byte("x"))
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			if got := f.headers[0].Get(tt.header); got != tt.want {
				t.Errorf("%s = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestLokiRetriesServerError(t *testing.T) {
	f := &fakeLoki{status: func(n int) int {
		if n == 1 {
			return http.StatusInternalServerError
		}
		return http.StatusNoContent
	}}
	l := newTestLoki(t, f, LokiConfig{})
	l.NewWriter().Write(Labels{"k": "v"}, []byte("x"))
	if err := l.Close(); err != nil {
		t.Fatalf("Close = %v, want success after a retry", err)
	}
	if got := f.calls.Load(); got != 2 {
		t.Errorf("calls = %d, want 2", got)
	}
}

func TestLokiGivesUpAfterAttempts(t *testing.T) {
	f := &fakeLoki{status: func(int) int { return http.StatusServiceUnavailable }}
	l := newTestLoki(t, f, LokiConfig{})
	l.NewWriter().Write(Labels{"k": "v"}, []byte("x"))
	err := l.Close()
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("Close = %v, want a 503 error", err)
	}
	if got := f.calls.Load(); got != 3 {
		t.Errorf("calls = %d, want 3", got)
	}
}

func TestLokiNoRetryOnClientError(t *testing.T) {
	f := &fakeLoki{status: func(int) int { return http.StatusBadRequest }}
	l := newTestLoki(t, f, LokiConfig{})
	l.NewWriter().Write(Labels{"k": "v"}, []byte("x"))
	if err := l.Close(); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("Close = %v, want a 400 error", err)
	}
	if got := f.calls.Load(); got != 1 {
		t.Errorf("calls = %d, want 1", got)
	}
}

func TestLokiDropsBatchesAfterFailure(t *testing.T) {
	f := &fakeLoki{status: func(int) int { return http.StatusUnauthorized }}
	l := newTestLoki(t, f, LokiConfig{BatchLines: 1, Senders: 1})
	w := l.NewWriter()
	w.Write(Labels{"k": "v"}, []byte("1"))
	// Wait for the first send to fail before writing more.
	deadline := time.Now().Add(5 * time.Second)
	for !l.failed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for range 10 {
		w.Write(Labels{"k": "v"}, []byte("x"))
	}
	if err := l.Close(); err == nil {
		t.Fatal("Close = nil, want an error")
	}
	if got := f.calls.Load(); got != 1 {
		t.Errorf("calls = %d, want 1", got)
	}
}

func TestLokiConcurrentWriters(t *testing.T) {
	f := &fakeLoki{}
	l := newTestLoki(t, f, LokiConfig{BatchLines: 7})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := l.NewWriter()
			for range 100 {
				w.Write(Labels{"k": "v"}, []byte("x"))
			}
		}()
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, b := range f.bodies {
		for _, s := range b.Streams {
			for _, v := range s.Values {
				seen[v[0]] = true
			}
		}
	}
	if len(seen) != 800 {
		t.Errorf("got %d unique entries, want 800", len(seen))
	}
}

func TestNewLokiRejectsBadURL(t *testing.T) {
	if _, err := NewLoki(LokiConfig{URL: "loki:3100"}); err == nil || !strings.Contains(err.Error(), "--loki") {
		t.Errorf("err = %v, want a --loki error", err)
	}
}
