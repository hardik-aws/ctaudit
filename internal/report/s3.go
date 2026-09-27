package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"text/tabwriter"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/s3log"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

//go:embed templates/s3.html.tmpl
var s3TemplateText string

var s3Template = template.Must(template.New("s3").Funcs(baseFuncs()).Funcs(template.FuncMap{
	"elbcss":    func() template.CSS { return template.CSS(elbStyleSheet) },
	"elbjs":     func() template.JS { return template.JS(elbScript) },
	"tone":      tone,
	"dash":      dashIfEmpty,
	"sevtone":   sevTone,
	"bytes":     humanBytes,
	"bytecount": func(n int) string { return humanBytes(int64(n)) },
	"ms": func(v int64) string {
		if v < 0 {
			return "-"
		}
		return fmt.Sprintf("%d ms", v)
	},
}).Parse(s3TemplateText))

// s3ByteTableTitles marks which of s3RankedTables' terminal titles hold
// byte counts rather than request counts, so the HTML and PDF renderers can
// format their values with humanBytes without changing rankedTable itself.
var s3ByteTableTitles = map[string]bool{
	"BYTES SENT BY REQUESTER": true,
	"BYTES SENT BY REMOTE IP": true,
}

// s3RankedTables lists the S3 counters in report order. Both renderers use
// it so the terminal and HTML reports agree.
func s3RankedTables(s *stats.S3Summary) []rankedTable {
	return []rankedTable{
		{"OPERATIONS", "OPERATION", "Operations", "Operation", s.ByOperation},
		{"REQUESTERS", "REQUESTER", "Requesters", "Requester", s.ByRequester},
		{"TOP REMOTE IPS", "REMOTE IP", "Top remote IPs", "Remote IP", s.ByRemoteIP},
		{"STATUS CODES", "STATUS", "Status codes", "Status", s.ByStatus},
		{"ERROR CODES", "ERROR CODE", "Error codes", "Error code", s.ByErrorCode},
		{"DENIED BY REMOTE IP", "REMOTE IP", "Denied by remote IP", "Remote IP", s.DeniedByIP},
		{"SOURCE BUCKETS", "BUCKET", "Source buckets", "Bucket", s.ByBucket},
		{"TOP KEYS", "BUCKET/KEY", "Top keys", "Bucket/key", s.ByKey},
		{"BYTES SENT BY REQUESTER", "REQUESTER", "Bytes sent by requester", "Requester", s.BytesByRequester},
		{"BYTES SENT BY REMOTE IP", "REMOTE IP", "Bytes sent by remote IP", "Remote IP", s.BytesByIP},
		{"TLS VERSIONS", "TLS", "TLS versions", "TLS", s.ByTLS},
		{"AUTH TYPES", "AUTH TYPE", "Auth types", "Auth type", s.ByAuthType},
		{"SIGNATURE VERSIONS", "SIGNATURE", "Signature versions", "Signature", s.BySigVersion},
		{"USER AGENTS", "USER AGENT", "User agents", "User agent", s.ByUserAgent},
	}
}

// s3TerminalTables is how many of s3RankedTables the terminal prints; none
// of the first six are byte tables, so the terminal never needs to format
// a count with humanBytes.
const s3TerminalTables = 6

// S3Terminal writes the plain-text S3 access log report.
func S3Terminal(w io.Writer, res engine.S3Result, meta Meta, topN int) error {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewS3Summary()
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	p := func(format string, a ...any) { fmt.Fprintf(tw, format, a...) }

	p("Amazon S3 Access Logs — %s .. %s (%d days)\n",
		meta.Since.Format(dayLayout), meta.Until.Format(dayLayout), meta.Days())
	p("Bucket: %s   Layout: %s   Source buckets: %s\n",
		clean(meta.Bucket), clean(res.Layout), groupDigits(len(res.SourceBuckets)))
	p("Objects scanned: %s   Records read: %s   Matched: %s   Elapsed: %s\n",
		groupDigits(res.ObjectsScanned), groupDigits(res.RecordsRead),
		groupDigits(res.MatchedRecords), formatElapsed(res.Elapsed))

	p("\nTRAFFIC\n")
	p("  Requests: %d   Errors: %d   Denied: %d   Anonymous: %d   Bytes sent: %s\n",
		sum.Total, sum.Errors, sum.Denied, sum.Anonymous, humanBytes(sum.BytesSent))

	p("\nFINDINGS (%d)\n", len(res.Findings))
	if len(res.Findings) == 0 {
		p("  none\n")
	} else {
		for _, f := range res.Findings {
			p("  [%s] %s — %s: %s\n", f.Severity, clean(f.Title), clean(f.Actor), clean(f.Detail))
		}
	}
	if res.FindingsDropped > 0 {
		p("  (%d further findings dropped at the cap)\n", res.FindingsDropped)
	}

	for _, t := range s3RankedTables(sum)[:s3TerminalTables] {
		pairs := t.counter.TopN(topN)
		if len(pairs) == 0 {
			continue
		}
		p("\n%s\n", t.title)
		p("  %s\tREQUESTS\n", t.keyHeader)
		for _, kv := range pairs {
			p("  %s\t%d\n", clean(kv.Key), kv.Count)
		}
	}

	if meta.Narrowed {
		p("\nMATCHING REQUESTS (showing %d of %d)\n", len(res.Matches), res.MatchedRecords)
		if len(res.Matches) > 0 {
			p("  TIME\tBUCKET\tOPERATION\tKEY\tSTATUS\tERROR\tREQUESTER\tREMOTE IP\tBYTES\tTLS\tUSER AGENT\n")
			for _, e := range res.Matches {
				p("  %s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
					formatTime(e.Time), clean(e.Bucket), clean(e.Operation), clean(e.Key), e.Status,
					dashIfEmpty(clean(e.ErrorCode)), dashIfEmpty(clean(e.Principal())), clean(e.RemoteIP),
					humanBytes(e.BytesSent), dashIfEmpty(clean(e.TLSVersion)),
					truncate(dashIfEmpty(clean(e.UserAgent)), userAgentWidth))
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

// s3HTMLView is everything the S3 HTML template reads.
type s3HTMLView struct {
	Meta           Meta
	Res            engine.S3Result
	Summary        *stats.S3Summary
	Since, Until   string
	Days           int
	Elapsed        string
	Generated      string
	BytesSent      string
	BucketCount    int
	RequesterCount int
	Tables         []htmlTable
	ByteTables     []htmlTable
	Hours          []actionBar
	Matches        []s3log.Entry
}

// S3HTML writes the self-contained S3 access log report.
func S3HTML(w io.Writer, res engine.S3Result, meta Meta, topN int) error {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewS3Summary()
	}
	v := s3HTMLView{
		Meta:           meta,
		Res:            res,
		Summary:        sum,
		Since:          meta.Since.Format(dayLayout),
		Until:          meta.Until.Format(dayLayout),
		Days:           meta.Days(),
		Elapsed:        formatElapsed(res.Elapsed),
		Generated:      formatTime(meta.GeneratedAt),
		BytesSent:      humanBytes(sum.BytesSent),
		BucketCount:    len(sum.ByBucket),
		RequesterCount: len(sum.ByRequester),
		Hours:          wafHourBars(sum.ByHour),
		Matches:        res.Matches,
	}
	for _, t := range s3RankedTables(sum) {
		pairs := t.counter.TopN(topN)
		if len(pairs) == 0 {
			continue
		}
		tbl := htmlTable{Title: t.htmlTitle, KeyHeader: t.htmlKey, Rows: bars(pairs)}
		if s3ByteTableTitles[t.title] {
			v.ByteTables = append(v.ByteTables, tbl)
		} else {
			v.Tables = append(v.Tables, tbl)
		}
	}
	return s3Template.Execute(w, v)
}

// S3PDF writes the printable S3 access log report.
func S3PDF(w io.Writer, res engine.S3Result, meta Meta, topN int) error {
	d, err := renderS3PDF(res, meta, topN)
	if err != nil {
		return err
	}
	return d.writeTo(w)
}
