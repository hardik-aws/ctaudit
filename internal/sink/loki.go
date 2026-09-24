package sink

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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
	// Start + n ns so every entry is unique. Defaults to time.Now().
	Start time.Time
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
	for _, w := range writers {
		w.flush()
	}
	l.wg.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return fmt.Errorf("loki push: %w", l.err)
	}
	return nil
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
		if err != nil {
			l.fail(err)
		}
	}()
}

type lokiStream struct {
	Stream Labels      `json:"stream"`
	Values [][2]string `json:"values"`
}

type lokiWriter struct {
	loki    *Loki
	streams map[string]*lokiStream
	order   []*lokiStream
	lines   int
	bytes   int
}

func (w *lokiWriter) Write(labels Labels, line []byte) {
	if w.loki.failed.Load() {
		return
	}
	k := labels.key()
	s := w.streams[k]
	if s == nil {
		s = &lokiStream{Stream: labels}
		w.streams[k] = s
		w.order = append(w.order, s)
	}
	ts := w.loki.base + w.loki.seq.Add(1)
	s.Values = append(s.Values, [2]string{strconv.FormatInt(ts, 10), string(line)})
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
