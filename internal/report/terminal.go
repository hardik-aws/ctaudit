// Package report renders an engine.Result for humans: a plain-text summary
// for the terminal and a single self-contained HTML file.
package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// Meta describes the scan that produced a Result: what the Result itself does
// not know, such as where the logs came from and what was asked for.
type Meta struct {
	Bucket   string
	Accounts []string
	Regions  []string
	// Since and Until are the first and last UTC days requested, both inclusive.
	Since time.Time
	Until time.Time
	// Narrowed is true when a filter specific enough to make listing
	// individual events useful was supplied (query.Filter.IsNarrowing).
	Narrowed    bool
	GeneratedAt time.Time
}

const (
	dayLayout      = "2006-01-02"
	timeLayout     = time.RFC3339
	maxErrorsShown = 10
	eventNameWidth = 22
)

// Days is the number of calendar days the scan covered.
func (m Meta) Days() int {
	if m.Until.Before(m.Since) {
		return 0
	}
	return int(m.Until.Sub(m.Since)/(24*time.Hour)) + 1
}

// Terminal writes the plain-text summary. topN bounds every ranked table.
func Terminal(w io.Writer, res engine.Result, meta Meta, topN int) error {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewSummary()
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	p := func(format string, a ...any) { fmt.Fprintf(tw, format, a...) }

	p("CloudTrail Audit — %s .. %s (%d days)\n",
		meta.Since.Format(dayLayout), meta.Until.Format(dayLayout), meta.Days())
	p("Bucket: %s   Accounts: %d   Regions: %d\n", clean(meta.Bucket), len(meta.Accounts), len(meta.Regions))
	p("Objects scanned: %s   Records read: %s   Matched: %s   Elapsed: %s\n",
		groupDigits(res.ObjectsScanned), groupDigits(res.RecordsRead),
		groupDigits(res.MatchedRecords), formatElapsed(res.Elapsed))

	p("\nSUMMARY\n")
	p("  Total events\t%d\n", sum.TotalEvents)
	p("  Write events\t%d\n", sum.WriteEvents)
	p("  Error events\t%d\n", sum.ErrorEvents)
	p("  First event\t%s\n", formatTime(sum.FirstEvent))
	p("  Last event\t%s\n", formatTime(sum.LastEvent))

	for _, t := range rankedTables(sum) {
		pairs := t.counter.TopN(topN)
		if len(pairs) == 0 {
			continue
		}
		p("\n%s\n", t.title)
		p("  %s\tEVENTS\n", t.keyHeader)
		for _, kv := range pairs {
			p("  %s\t%d\n", clean(kv.Key), kv.Count)
		}
	}

	p("\nFINDINGS (%d)\n", len(res.Findings))
	if len(res.Findings) == 0 {
		p("  none\n")
	} else {
		p("  SEV\tTIME\tRULE\tACTOR\tDETAIL\n")
		for _, f := range res.Findings {
			p("  %s\t%s\t%s\t%s\t%s\n", f.Severity, formatTime(f.Time),
				clean(f.Rule), clean(f.Actor), clean(f.Detail))
		}
	}
	if res.DroppedFindings > 0 {
		p("  (%d further findings dropped at the cap)\n", res.DroppedFindings)
	}

	if meta.Narrowed {
		p("\nMATCHING EVENTS (showing %d of %d)\n", len(res.Matches), res.MatchedRecords)
		if len(res.Matches) > 0 {
			p("  TIME\tACCOUNT\tREGION\tEVENT NAME\tACTOR\tSOURCE IP\tERROR\n")
			for _, r := range res.Matches {
				p("  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", formatTime(r.EventTime),
					clean(r.RecipientAccountID), clean(r.AWSRegion),
					truncate(clean(r.EventName), eventNameWidth), clean(r.Actor()),
					clean(r.SourceIPAddress), clean(r.ErrorCode))
			}
		}
	}

	if len(res.Errors) > 0 {
		p("\nERRORS (%d)\n", len(res.Errors))
		for i, e := range res.Errors {
			if i == maxErrorsShown {
				p("  ... %d more\n", len(res.Errors)-i)
				break
			}
			p("  %s\n", clean(e))
		}
	}

	return tw.Flush()
}

// rankedTable pairs a counter with the headings it is printed under. Both
// renderers use the same list so the terminal and HTML reports agree.
type rankedTable struct {
	title     string // terminal heading
	keyHeader string // terminal column heading
	htmlTitle string
	htmlKey   string
	counter   stats.Counter
}

func rankedTables(s *stats.Summary) []rankedTable {
	return []rankedTable{
		{"TOP PRINCIPALS", "PRINCIPAL", "Top principals", "Principal", s.ByPrincipal},
		{"TOP EVENTS", "EVENT NAME", "Top event names", "Event name", s.ByEventName},
		{"TOP SERVICES", "SERVICE", "Top services", "Service", s.ByService},
		{"TOP ERROR CODES", "ERROR CODE", "Top error codes", "Error code", s.ByErrorCode},
		{"TOP SOURCE IPS", "SOURCE IP", "Top source IPs", "Source IP", s.BySourceIP},
		{"BY ACCOUNT", "ACCOUNT", "By account", "Account", s.ByAccount},
		{"BY REGION", "REGION", "By region", "Region", s.ByRegion},
	}
}

// clean replaces control characters with spaces. CloudTrail fields such as
// user names and request details are caller-controlled, so printing them raw
// would let a crafted value inject terminal escape sequences or break the
// tab-aligned columns.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-2] + ".."
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(timeLayout)
}

func formatElapsed(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

// groupDigits renders 3914660 as "3,914,660".
func groupDigits(n int) string {
	s := strconv.Itoa(n)
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return sign + b.String()
}
