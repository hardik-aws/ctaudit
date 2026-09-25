package sink

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"
)

const jsonlFlushBytes = 256 << 10

// JSONL writes every line to a local JSON Lines file. Labels are not
// written; each line already carries its own fields.
type JSONL struct {
	path    string
	mu      sync.Mutex
	file    *os.File
	out     *bufio.Writer
	writers []*jsonlWriter
	err     error
}

// NewJSONL creates (or truncates) path.
func NewJSONL(path string) (*JSONL, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("--jsonl: %w", err)
	}
	return &JSONL{path: path, file: f, out: bufio.NewWriter(f)}, nil
}

// NewWriter returns a writer with its own buffer.
func (j *JSONL) NewWriter() Writer {
	w := &jsonlWriter{j: j}
	j.mu.Lock()
	j.writers = append(j.writers, w)
	j.mu.Unlock()
	return w
}

// Close flushes every writer and closes the file.
func (j *JSONL) Close() error {
	j.mu.Lock()
	writers := j.writers
	j.writers = nil
	j.mu.Unlock()
	for _, w := range writers {
		w.flush()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.out.Flush(); err != nil && j.err == nil {
		j.err = err
	}
	if err := j.file.Close(); err != nil && j.err == nil {
		j.err = err
	}
	if j.err != nil {
		return fmt.Errorf("write %s: %w", j.path, j.err)
	}
	return nil
}

type jsonlWriter struct {
	j   *JSONL
	buf []byte
}

func (w *jsonlWriter) Write(_ Labels, _ time.Time, line []byte) {
	w.buf = append(w.buf, line...)
	w.buf = append(w.buf, '\n')
	if len(w.buf) >= jsonlFlushBytes {
		w.flush()
	}
}

func (w *jsonlWriter) flush() {
	if len(w.buf) == 0 {
		return
	}
	w.j.mu.Lock()
	if w.j.err == nil {
		_, w.j.err = w.j.out.Write(w.buf)
	}
	w.j.mu.Unlock()
	w.buf = w.buf[:0]
}
