package sink

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLokiEventTimeSortsEachStream(t *testing.T) {
	f := &fakeLoki{}
	start := time.Unix(1_800_000_000, 0)
	l := newTestLoki(t, f, LokiConfig{Start: start, EventTime: true, BatchLines: 2, Senders: 4})
	t0 := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	ev := Labels{"kind": "request", "lb": "a"}
	other := Labels{"kind": "request", "lb": "b"}
	w1, w2 := l.NewWriter(), l.NewWriter()
	w1.Write(ev, t0.Add(3*time.Minute), []byte("3"))
	w2.Write(ev, t0.Add(1*time.Minute), []byte("1"))
	w1.Write(other, t0, []byte("b0"))
	w2.Write(ev, t0.Add(2*time.Minute), []byte("2"))
	w1.Write(ev, time.Time{}, []byte("untimed"))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Two lines per push and one sender: the pushes arrive in order.
	var got []string
	for _, b := range f.bodies {
		n := 0
		for _, s := range b.Streams {
			for _, v := range s.Values {
				got = append(got, s.Stream["lb"]+":"+v[1]+"@"+v[0])
				n++
			}
		}
		if n > 2 {
			t.Errorf("push of %d lines, want at most 2", n)
		}
	}
	ns := func(d time.Duration) string { return strconv.FormatInt(t0.Add(d).UnixNano(), 10) }
	want := []string{
		"a:1@" + ns(time.Minute), "a:2@" + ns(2*time.Minute), "a:3@" + ns(3*time.Minute),
		"a:untimed@" + strconv.FormatInt(start.UnixNano()+1, 10), "b:b0@" + ns(0),
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("pushed\n %v\nwant\n %v", got, want)
	}
}

func TestLokiEventTimeMaxLines(t *testing.T) {
	f := &fakeLoki{}
	l := newTestLoki(t, f, LokiConfig{EventTime: true, MaxLines: 2})
	w := l.NewWriter()
	for i := 0; i < 3; i++ {
		w.Write(Labels{"k": "v"}, time.Now(), []byte("x"))
	}
	err := l.Close()
	if err == nil || !strings.Contains(err.Error(), "--loki-time scan") {
		t.Fatalf("Close = %v, want the MaxLines error", err)
	}
	if len(f.bodies) != 0 {
		t.Errorf("pushed %d batches after the cap", len(f.bodies))
	}
}

func TestLokiTooOldIsNotFatal(t *testing.T) {
	srv := func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `entry for stream '{k="v"}' has timestamp too old: 2026-01-01T00:00:00Z`, http.StatusBadRequest)
	}
	l := newTestLokiHandler(t, http.HandlerFunc(srv), LokiConfig{EventTime: true})
	l.NewWriter().Write(Labels{"k": "v"}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), []byte("x"))
	if err := l.Close(); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}
	if l.Rejected() != 1 {
		t.Errorf("Rejected = %d, want 1", l.Rejected())
	}

	scan := newTestLokiHandler(t, http.HandlerFunc(srv), LokiConfig{})
	scan.NewWriter().Write(Labels{"k": "v"}, time.Time{}, []byte("x"))
	if err := scan.Close(); err == nil {
		t.Error("too-old 400 in scan mode did not fail Close")
	}

	bad := newTestLokiHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid labels", http.StatusBadRequest)
	}), LokiConfig{EventTime: true})
	bad.NewWriter().Write(Labels{"k": "v"}, time.Now(), []byte("x"))
	if err := bad.Close(); err == nil {
		t.Error("other 400 did not fail Close")
	}
}
