package sink

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRedactURL(t *testing.T) {
	if got := redactURL("https://bob:hunter2@loki.example/x"); strings.Contains(got, "hunter2") {
		t.Errorf("redactURL kept the password: %q", got)
	}
}

func TestLokiDebugLogsAttemptsWithoutSecrets(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	l, err := NewLoki(LokiConfig{URL: srv.URL, Auth: Auth{Token: "sekrit-token"}, Backoff: time.Millisecond, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	w := l.NewWriter()
	w.Write(Labels{"job": "ctaudit"}, []byte(`{"secret_field":"record-body"}`))
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`msg="http post"`, "sink=loki", "attempt=1", "retry=true", "attempt=2", "lines=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("debug output missing %q:\n%s", want, out)
		}
	}
	for _, leak := range []string{"sekrit-token", "record-body", "Bearer"} {
		if strings.Contains(out, leak) {
			t.Errorf("debug output leaks %q:\n%s", leak, out)
		}
	}
}
