package sink

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// LokiConfig configures a Loki sink. Zero values take the defaults noted.
type LokiConfig struct {
	// URL is the Loki base URL; lines are posted to URL/loki/api/v1/push.
	URL string
	// Tenant, when set, is sent as the X-Scope-OrgID header.
	Tenant string
	Auth   Auth
	// Client defaults to a client with a 30s timeout.
	Client *http.Client
	// BatchBytes (default 1 MiB) and BatchLines (default 5000) bound one
	// writer's batch.
	BatchBytes int
	BatchLines int
	// Senders (default 4) bounds the batches in flight.
	Senders int
	// Attempts (default 3) and Backoff (default 500ms, doubling) control
	// retries.
	Attempts int
	Backoff  time.Duration
	// Start is the base timestamp of every entry; entry n is sent at
	// Start + n ns so every entry is unique. Defaults to time.Now(). In
	// EventTime mode it stamps only lines that carry no record time.
	Start time.Time
	// EventTime stamps each line with the time of its record instead of the
	// scan time, so Grafana's time picker selects request and event times.
	// Loki only accepts a stream's lines in order within its out-of-order
	// window, so the sink buffers every line until Close, sorts each stream
	// oldest first, and pushes with one sender.
	EventTime bool
	// MaxLines (default 2,000,000) caps the lines EventTime mode buffers.
	// Past it the sink fails rather than grow without bound.
	MaxLines int
	// Log, when set, gets one debug line per push attempt.
	Log *slog.Logger
}

// Loki streams lines to the Loki push API.
type Loki struct {
	cfg    LokiConfig
	url    string
	base   int64
	seq    atomic.Int64
	slots  chan struct{}
	wg     sync.WaitGroup
	failed atomic.Bool
	// buffered counts the lines held in EventTime mode.
	buffered atomic.Int64
	// rejected counts pushes Loki refused in part because entries were
	// older than its limits (see tooOld).
	rejected atomic.Int64

	mu      sync.Mutex
	writers []*lokiWriter
	err     error
}

// NewLoki validates cfg and returns a Loki sink.
func NewLoki(cfg LokiConfig) (*Loki, error) {
	if err := CheckURL(cfg.URL); err != nil {
		return nil, fmt.Errorf("--loki: %w", err)
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.BatchBytes <= 0 {
		cfg.BatchBytes = 1 << 20
	}
	if cfg.BatchLines <= 0 {
		cfg.BatchLines = 5000
	}
	if cfg.Senders <= 0 {
		cfg.Senders = 4
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = 3
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 500 * time.Millisecond
	}
	if cfg.Start.IsZero() {
		cfg.Start = time.Now()
	}
	if cfg.MaxLines <= 0 {
		cfg.MaxLines = 2_000_000
	}
	if cfg.EventTime {
		cfg.Senders = 1
	}
	return &Loki{
		cfg:   cfg,
		url:   strings.TrimRight(cfg.URL, "/") + "/loki/api/v1/push",
		base:  cfg.Start.UnixNano(),
		slots: make(chan struct{}, cfg.Senders),
	}, nil
}

// NewWriter returns a writer with its own batch.
func (l *Loki) NewWriter() Writer {
	w := &lokiWriter{loki: l, streams: map[string]*lokiStream{}}
	l.mu.Lock()
	l.writers = append(l.writers, w)
	l.mu.Unlock()
	return w
}

// Close flushes every writer, waits for all sends, and returns the first
// error.
func (l *Loki) Close() error {
	l.mu.Lock()
	writers := l.writers
	l.writers = nil
	l.mu.Unlock()
	if l.cfg.EventTime {
		l.pushSorted(writers)
	} else {
		for _, w := range writers {
			w.flush()
		}
	}
	l.wg.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return fmt.Errorf("loki push: %w", l.err)
	}
	return nil
}

// Rejected returns how many pushes Loki refused in part because some
// entries were too old or too far behind the newest entry of their stream.
// In EventTime mode Loki keeps the other entries of such a push, so these do
// not fail Close; in scan mode they fail it like any other 400.
func (l *Loki) Rejected() int64 { return l.rejected.Load() }

// pushSorted merges the writers' streams, sorts each stream by timestamp,
// and sends them in batches. With one sender the batches reach Loki in
// order, so each stream arrives oldest first.
func (l *Loki) pushSorted(writers []*lokiWriter) {
	if l.failed.Load() {
		return
	}
	merged := map[string]*lokiStream{}
	var order []string
	for _, w := range writers {
		for _, s := range w.order {
			k := s.Stream.key()
			m := merged[k]
			if m == nil {
				m = &lokiStream{Stream: s.Stream}
				merged[k] = m
				order = append(order, k)
			}
			m.Values = append(m.Values, s.Values...)
			m.ts = append(m.ts, s.ts...)
		}
		w.streams, w.order, w.lines, w.bytes = nil, nil, 0, 0
	}
	sort.Strings(order)
	var batch []*lokiStream
	lines, size := 0, 0
	flush := func() {
		if lines > 0 {
			l.send(batch, lines)
		}
		batch, lines, size = nil, 0, 0
	}
	for _, k := range order {
		s := merged[k]
		sort.Stable(byTS{s})
		part := &lokiStream{Stream: s.Stream}
		for _, v := range s.Values {
			if part.Values == nil {
				batch = append(batch, part)
			}
			part.Values = append(part.Values, v)
			lines++
			size += len(v[1])
			if lines >= l.cfg.BatchLines || size >= l.cfg.BatchBytes {
				flush()
				part = &lokiStream{Stream: s.Stream}
			}
		}
	}
	flush()
}

// byTS sorts a stream's values and timestamps together.
type byTS struct{ s *lokiStream }

func (b byTS) Len() int           { return len(b.s.ts) }
func (b byTS) Less(i, j int) bool { return b.s.ts[i] < b.s.ts[j] }
func (b byTS) Swap(i, j int) {
	b.s.ts[i], b.s.ts[j] = b.s.ts[j], b.s.ts[i]
	b.s.Values[i], b.s.Values[j] = b.s.Values[j], b.s.Values[i]
}

// tooOld reports whether err is Loki refusing entries for their age: older
// than reject_old_samples_max_age, or behind the stream's out-of-order
// window. Loki accepts the rest of the push in that case.
func tooOld(err error) bool {
	var se *statusError
	if !errors.As(err, &se) || se.code != http.StatusBadRequest {
		return false
	}
	return strings.Contains(se.body, "too far behind") || strings.Contains(se.body, "too old")
}

func (l *Loki) fail(err error) {
	l.mu.Lock()
	if l.err == nil {
		l.err = err
	}
	l.mu.Unlock()
	l.failed.Store(true)
}

// send posts one batch in the background. It blocks while every sender is
// busy, which applies back-pressure to the scan.
func (l *Loki) send(streams []*lokiStream, lines int) {
	if l.failed.Load() {
		return
	}
	body, err := encodePush(streams)
	if err != nil {
		l.fail(err)
		return
	}
	l.slots <- struct{}{}
	l.wg.Add(1)
	go func() {
		defer func() { <-l.slots; l.wg.Done() }()
		if l.failed.Load() {
			return
		}
		err := post(context.Background(), l.cfg.Client, l.url, body, l.cfg.Attempts, l.cfg.Backoff, func(r *http.Request) {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Content-Encoding", "gzip")
			if l.cfg.Tenant != "" {
				r.Header.Set("X-Scope-OrgID", l.cfg.Tenant)
			}
			l.cfg.Auth.apply(r)
		}, l.cfg.Log, "sink", "loki", "streams", len(streams), "lines", lines)
		switch {
		case err == nil:
		case l.cfg.EventTime && tooOld(err):
			// Retrying cannot make an entry younger, so count it and
			// keep going; a failure here would fail every serve tick.
			l.rejected.Add(1)
		default:
			l.fail(err)
		}
	}()
}

type lokiStream struct {
	Stream Labels      `json:"stream"`
	Values [][2]string `json:"values"`
	// ts holds the Values timestamps as numbers, in EventTime mode only.
	ts []int64
}

type lokiWriter struct {
	loki    *Loki
	streams map[string]*lokiStream
	order   []*lokiStream
	lines   int
	bytes   int
}

func (w *lokiWriter) Write(labels Labels, t time.Time, line []byte) {
	if w.loki.failed.Load() {
		return
	}
	event := w.loki.cfg.EventTime
	if event && w.loki.buffered.Add(1) > int64(w.loki.cfg.MaxLines) {
		w.loki.fail(fmt.Errorf("event-time mode buffers every line until the scan ends and more than %d matched; "+
			"use --loki-time scan or a shorter window", w.loki.cfg.MaxLines))
		w.streams, w.order, w.lines, w.bytes = map[string]*lokiStream{}, nil, 0, 0
		return
	}
	k := labels.key()
	s := w.streams[k]
	if s == nil {
		s = &lokiStream{Stream: labels}
		w.streams[k] = s
		w.order = append(w.order, s)
	}
	var ts int64
	if event && !t.IsZero() {
		ts = t.UnixNano()
	} else {
		ts = w.loki.base + w.loki.seq.Add(1)
	}
	s.Values = append(s.Values, [2]string{strconv.FormatInt(ts, 10), string(line)})
	if event {
		s.ts = append(s.ts, ts)
		return
	}
	w.lines++
	w.bytes += len(line)
	if w.lines >= w.loki.cfg.BatchLines || w.bytes >= w.loki.cfg.BatchBytes {
		w.flush()
	}
}

func (w *lokiWriter) flush() {
	if w.lines == 0 {
		return
	}
	batch, lines := w.order, w.lines
	w.streams = map[string]*lokiStream{}
	w.order = nil
	w.lines, w.bytes = 0, 0
	w.loki.send(batch, lines)
}

func encodePush(streams []*lokiStream) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(struct {
		Streams []*lokiStream `json:"streams"`
	}{streams}); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
