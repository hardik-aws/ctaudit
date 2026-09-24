package sink

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Metrics builds a Prometheus text-format body of gauges and counters.
// Families are written in the order they were first added, and a family
// keeps the type of its first sample.
type Metrics struct {
	order    []string
	families map[string]*family
}

type family struct {
	help    string
	typ     string
	samples []sample
}

type sample struct {
	labels string
	value  float64
}

// NewMetrics returns an empty set.
func NewMetrics() *Metrics { return &Metrics{families: map[string]*family{}} }

// Gauge adds an unlabeled gauge.
func (m *Metrics) Gauge(name, help string, v float64) { m.add("gauge", name, help, "", v) }

// GaugeWith adds one labeled sample of a gauge family.
func (m *Metrics) GaugeWith(name, help, label, value string, v float64) {
	m.add("gauge", name, help, labelSet(map[string]string{label: value}), v)
}

// GaugeLabels adds one sample of a gauge family with any number of labels.
func (m *Metrics) GaugeLabels(name, help string, labels map[string]string, v float64) {
	m.add("gauge", name, help, labelSet(labels), v)
}

// Counter adds an unlabeled counter.
func (m *Metrics) Counter(name, help string, v float64) { m.add("counter", name, help, "", v) }

// CounterWith adds one labeled sample of a counter family.
func (m *Metrics) CounterWith(name, help, label, value string, v float64) {
	m.add("counter", name, help, labelSet(map[string]string{label: value}), v)
}

// CounterLabels adds one sample of a counter family with any number of labels.
func (m *Metrics) CounterLabels(name, help string, labels map[string]string, v float64) {
	m.add("counter", name, help, labelSet(labels), v)
}

// labelSet renders labels sorted by name, with every value escaped.
func labelSet(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	names := make([]string, 0, len(labels))
	for k := range labels {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, k := range names {
		parts[i] = fmt.Sprintf(`%s="%s"`, k, escapeLabel(labels[k]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func (m *Metrics) add(typ, name, help, labels string, v float64) {
	f := m.families[name]
	if f == nil {
		f = &family{help: help, typ: typ}
		m.families[name] = f
		m.order = append(m.order, name)
	}
	f.samples = append(f.samples, sample{labels, v})
}

// Text renders the Prometheus text exposition format.
func (m *Metrics) Text() string {
	var b strings.Builder
	for _, name := range m.order {
		f := m.families[name]
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, f.help, name, f.typ)
		for _, s := range f.samples {
			fmt.Fprintf(&b, "%s%s %s\n", name, s.labels, strconv.FormatFloat(s.value, 'g', -1, 64))
		}
	}
	return b.String()
}

// Names returns the family names, sorted; tests use it.
func (m *Metrics) Names() []string {
	out := append([]string(nil), m.order...)
	sort.Strings(out)
	return out
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

var jobPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Pushgateway sends metrics to a Prometheus Pushgateway.
type Pushgateway struct {
	URL        string
	Job        string
	Subcommand string
	Auth       Auth
	// Client defaults to a client with a 30s timeout.
	Client *http.Client
	// Attempts (default 3) and Backoff (default 500ms) control retries.
	Attempts int
	Backoff  time.Duration
	// Log, when set, gets one debug line per push attempt.
	Log *slog.Logger
}

// Check validates the URL and job before any scan starts.
func (p *Pushgateway) Check() error {
	if err := CheckURL(p.URL); err != nil {
		return fmt.Errorf("--pushgateway: %w", err)
	}
	if !jobPattern.MatchString(p.Job) {
		return fmt.Errorf("--push-job: %q may contain only letters, digits, '_', '.', and '-'", p.Job)
	}
	return nil
}

// Endpoint is the grouping-key URL the metrics are POSTed to.
func (p *Pushgateway) Endpoint() string {
	return strings.TrimRight(p.URL, "/") + "/metrics/job/" + url.PathEscape(p.Job) +
		"/subcommand/" + url.PathEscape(p.Subcommand)
}

// Push POSTs m, which replaces only the families in m under this grouping
// key.
func (p *Pushgateway) Push(ctx context.Context, m *Metrics) error {
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	attempts, backoff := p.Attempts, p.Backoff
	if attempts <= 0 {
		attempts = 3
	}
	if backoff <= 0 {
		backoff = 500 * time.Millisecond
	}
	err := post(ctx, client, p.Endpoint(), []byte(m.Text()), attempts, backoff, func(r *http.Request) {
		r.Header.Set("Content-Type", "text/plain; version=0.0.4")
		p.Auth.apply(r)
	}, p.Log, "sink", "pushgateway")
	if err != nil {
		return fmt.Errorf("pushgateway push: %w", err)
	}
	return nil
}
