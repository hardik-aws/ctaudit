// Package sink ships ctaudit's results to observability backends: log lines
// to Loki or a JSON Lines file, and summary metrics to a Prometheus
// Pushgateway. It uses only the standard library.
package sink

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Labels are the Loki stream labels of one line. Keep them low-cardinality:
// never put IPs, user agents, ARNs, or run IDs here.
type Labels map[string]string

// key returns a canonical form of l, used to group lines into streams.
func (l Labels) key() string {
	names := make([]string, 0, len(l))
	for k := range l {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, k := range names {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(l[k])
		b.WriteByte(0)
	}
	return b.String()
}

// Writer accepts log lines. A Writer belongs to one goroutine; it is not
// safe for concurrent use. Errors are reported by the owning Sink's Close.
// t is the time of the record the line describes; the zero time means it
// has none. Sinks that stamp lines themselves may ignore it.
type Writer interface {
	Write(labels Labels, t time.Time, line []byte)
}

// Sink hands out per-goroutine writers. NewWriter is safe for concurrent
// use. Close flushes every writer, waits for in-flight sends, and returns
// the first error; no writer may be used after Close.
type Sink interface {
	NewWriter() Writer
	Close() error
}

// Multi fans every line out to all of sinks.
func Multi(sinks ...Sink) Sink {
	return multi(sinks)
}

type multi []Sink

func (m multi) NewWriter() Writer {
	ws := make(multiWriter, len(m))
	for i, s := range m {
		ws[i] = s.NewWriter()
	}
	return ws
}

func (m multi) Close() error {
	var errs []error
	for _, s := range m {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type multiWriter []Writer

func (m multiWriter) Write(labels Labels, t time.Time, line []byte) {
	for _, w := range m {
		w.Write(labels, t, line)
	}
}

// Auth is the credential for one HTTP target. The zero value sends no
// Authorization header.
type Auth struct {
	User, Password string
	Token          string
}

// AuthFromEnv reads <prefix>_USER, <prefix>_PASSWORD, and <prefix>_TOKEN.
// Setting a token together with a user, or a password without a user, is an
// error.
func AuthFromEnv(prefix string, getenv func(string) string) (Auth, error) {
	a := Auth{
		User:     getenv(prefix + "_USER"),
		Password: getenv(prefix + "_PASSWORD"),
		Token:    getenv(prefix + "_TOKEN"),
	}
	if a.Token != "" && (a.User != "" || a.Password != "") {
		return Auth{}, fmt.Errorf("set either %s_TOKEN or %s_USER and %s_PASSWORD, not both", prefix, prefix, prefix)
	}
	if a.Password != "" && a.User == "" {
		return Auth{}, fmt.Errorf("%s_PASSWORD is set but %s_USER is not", prefix, prefix)
	}
	return a, nil
}

func (a Auth) apply(r *http.Request) {
	switch {
	case a.Token != "":
		r.Header.Set("Authorization", "Bearer "+a.Token)
	case a.User != "":
		r.SetBasicAuth(a.User, a.Password)
	}
}

// CheckURL rejects anything but an absolute http or https URL with a host.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%q is not an http:// or https:// URL", raw)
	}
	return nil
}
