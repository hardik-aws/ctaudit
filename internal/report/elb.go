package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

//go:embed templates/elb.html.tmpl
var elbTemplateText string

// The ELB report carries its own stylesheet and a small script for sorting
// and filtering tables, both inlined so the file stays self-contained.
var (
	//go:embed templates/elb.css
	elbStyleSheet string
	//go:embed templates/elb.js
	elbScript string
)

var elbTemplate = template.Must(template.New("elb").Funcs(baseFuncs()).Funcs(template.FuncMap{
	"bytes":   humanBytes,
	"latency": formatLatency,
	"dash":    dashIfEmpty,
	"num64":   func(n int64) string { return groupDigits(int(n)) },
	"elbcss":  func() template.CSS { return template.CSS(elbStyleSheet) },
	"elbjs":   func() template.JS { return template.JS(elbScript) },
	"tone":    tone,
	"secs":    sortSeconds,
	"gauge":   gaugeSVG,
	"pctf":    func(v float64) string { return fmt.Sprintf("%.1f%%", v) },
	"dict": func(kv ...any) map[string]any {
		m := make(map[string]any, len(kv)/2)
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	},
}).Parse(elbTemplateText))

// tone classifies a table value for colour coding: "crit", "warn", "ok",
// "info", or "" for plain. It recognises HTTP status codes, TLS protocol
// names (SSLv3, TLSv1 and TLSv1.1 are weak), the listener/TLS keys built by
// stats.ConnSummary, and client certificate verify results.
func tone(v string) string {
	v = strings.TrimSpace(v)
	if len(v) == 3 && v[0] >= '1' && v[0] <= '5' && strings.Trim(v, "0123456789") == "" {
		switch v[0] {
		case '5':
			return "crit"
		case '4':
			return "warn"
		case '2':
			return "ok"
		default:
			return "info"
		}
	}
	listener, proto, found := strings.Cut(v, " ")
	if !found {
		listener, proto = "", v
	}
	switch {
	case isWeakTLS(proto):
		return "crit"
	case proto == "no TLS" && listener == "443":
		return "crit"
	case proto == "unknown":
		return "warn"
	case proto == "TLSv1.3":
		return "ok"
	case strings.HasPrefix(v, "Failed"):
		return "crit"
	case v == "Success":
		return "ok"
	}
	return ""
}

// isWeakTLS reports whether a protocol name is deprecated (RFC 8996).
func isWeakTLS(proto string) bool {
	switch proto {
	case "SSLv3", "TLSv1", "TLSv1.1":
		return true
	}
	return false
}

// sortSeconds renders a duration in seconds as a sort key; unmeasured (-1)
// values sort first.
func sortSeconds(s float64) string {
	if s < 0 {
		return "-1"
	}
	return strconv.FormatFloat(s, 'f', -1, 64)
}

// weakTLS counts entries in a protocol counter that use a deprecated protocol.
func weakTLS(c stats.Counter) int {
	n := 0
	for k, v := range c {
		if isWeakTLS(k) {
			n += v
		}
	}
	return n
}

const (
	pathWidth      = 60
	userAgentWidth = 40
)

// elbRankedTables lists the ELB counters in report order. Both renderers use
// it so the terminal and HTML reports agree.
func elbRankedTables(s *stats.ELBSummary) []rankedTable {
	return []rankedTable{
		{"BY LOAD BALANCER", "LOAD BALANCER", "By load balancer", "Load balancer", s.ByLB},
		{"BY STATUS", "ELB STATUS", "By ELB status", "Status", s.ByStatus},
		{"BY TARGET STATUS", "TARGET STATUS", "By target status", "Target status", s.ByTargetStatus},
		{"TOP CLIENT IPS", "CLIENT IP", "Top client IPs", "Client IP", s.ByClientIP},
		{"TOP HOSTS", "HOST / SNI", "Top hosts", "Host / SNI", s.ByHost},
		{"TOP PATHS", "PATH (numbers as {n})", "Top paths", "Path (numbers as {n})", s.ByPath},
		{"TOP USER AGENTS", "USER AGENT", "Top user agents", "User agent", s.ByUserAgent},
		{"TOP TARGETS", "TARGET", "Top targets", "Target", s.ByTarget},
		{"BY METHOD", "METHOD", "By method", "Method", s.ByMethod},
		{"BY LISTENER TYPE", "TYPE", "By listener type", "Type", s.ByType},
		{"BY ACTION", "ACTION", "By action", "Action", s.ByAction},
		{"BY TLS PROTOCOL", "TLS PROTOCOL", "By TLS protocol", "TLS protocol", s.BySSLProtocol},
		{"BY TLS CIPHER", "TLS CIPHER", "By TLS cipher", "TLS cipher", s.BySSLCipher},
		{"TOP ERROR REASONS", "ERROR REASON", "Top error reasons", "Error reason", s.ByErrorReason},
	}
}

// connRankedTables lists the connection log counters in report order.
func connRankedTables(s *stats.ConnSummary) []rankedTable {
	return []rankedTable{
		{"CONNECTIONS BY LOAD BALANCER", "LOAD BALANCER", "Connections by load balancer", "Load balancer", s.ByLB},
		{"CONNECTIONS BY LISTENER AND TLS", "LISTENER TLS", "By listener and TLS protocol", "Listener / TLS", s.ByListenerTLS},
		{"CONNECTIONS BY TLS PROTOCOL", "TLS PROTOCOL", "Connections by TLS protocol", "TLS protocol", s.ByProtocol},
		{"CONNECTIONS BY TLS CIPHER", "TLS CIPHER", "Connections by TLS cipher", "TLS cipher", s.ByCipher},
		{"CONNECTIONS BY KEY EXCHANGE", "KEY EXCHANGE", "By TLS key exchange", "Key exchange", s.ByKeyExchange},
		{"CONNECTIONS BY VERIFY STATUS", "VERIFY STATUS", "By client cert verify status", "Verify status", s.ByVerify},
		{"TOP CONNECTION CLIENT IPS", "CLIENT IP", "Top connection client IPs", "Client IP", s.ByClientIP},
		{"TOP FAILED HANDSHAKE CLIENT IPS", "CLIENT IP", "Top failed handshake client IPs", "Client IP", s.ByFailedClientIP},
	}
}

// ELBTerminal writes the plain-text load balancer report.
func ELBTerminal(w io.Writer, res engine.ELBResult, meta Meta, topN int) error {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewELBSummary()
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	p := func(format string, a ...any) { fmt.Fprintf(tw, format, a...) }

	p("ELB Access Logs — %s .. %s (%d days)\n",
		meta.Since.Format(dayLayout), meta.Until.Format(dayLayout), meta.Days())
	p("Bucket: %s   Accounts: %d   Regions: %d\n", clean(meta.Bucket), len(meta.Accounts), len(meta.Regions))
	p("Objects scanned: %s   Requests read: %s   Matched: %s   Connections read: %s   Elapsed: %s\n",
		groupDigits(res.ObjectsScanned), groupDigits(res.RecordsRead),
		groupDigits(res.MatchedRecords), groupDigits(res.ConnsRead), formatElapsed(res.Elapsed))

	p("\nTRAFFIC\n")
	p("  Requests\t%s\n", groupDigits(sum.Total))
	p("  Received\t%s\n", humanBytes(sum.ReceivedBytes))
	p("  Sent\t%s\n", humanBytes(sum.SentBytes))
	p("  4xx\t%s\n", groupDigits(sum.Errors4xx))
	p("  5xx\t%s\n", groupDigits(sum.Errors5xx))
	p("  Latency avg\t%s\n", formatLatency(sum.AvgLatency()))
	p("  Latency max\t%s\n", formatLatency(sum.LatencyMax))
	p("  First request\t%s\n", formatTime(sum.First))
	p("  Last request\t%s\n", formatTime(sum.Last))

	if sum.Total > 0 {
		p("\nHEALTH\n")
		for _, g := range healthGauges(sum) {
			p("  %s\t%s\t%s\t%s\n", g.Title, g.Value, strings.ToUpper(g.Tone), g.Hint)
		}
	}

	if groups := groupRows(sum, topN); len(groups) > 0 {
		p("\nTARGET GROUPS\n")
		p("  TARGET GROUP\tREQUESTS\t2XX\t4XX\t5XX\tELB 5XX\tCONN ERRORS\tTARGETS\tTARGET TIME AVG\tMAX\n")
		for _, g := range groups {
			p("  %s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", clean(g.Name), g.Requests, g.T2xx, g.T4xx, g.T5xx,
				g.ELB5xx, g.ConnErrors, g.Targets, formatLatency(g.Avg), formatLatency(g.Max))
		}
	}

	if paths := pathRows(sum, topN); len(paths) > 0 {
		p("\nSLOWEST PATHS\n")
		p("  PATH\tREQUESTS\tMIN\tAVG\tMAX\n")
		for _, r := range paths {
			p("  %s\t%d\t%s\t%s\t%s\n", clean(r.Path), r.Count, formatLatency(r.Min), formatLatency(r.Avg), formatLatency(r.Max))
		}
	}

	for _, t := range elbRankedTables(sum) {
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

	if sum.Total > 0 {
		p("\nREQUESTS BY HOUR (UTC)\n")
		for h := 0; h < 24; h++ {
			if n := sum.ByHour[strconv.Itoa(h)]; n > 0 {
				p("  %s\t%d\n", twoDigits(h), n)
			}
		}
	}

	if conns := res.Conns; conns != nil && conns.Total > 0 {
		p("\nTLS CONNECTIONS\n")
		p("  Connections\t%s\n", groupDigits(conns.Total))
		p("  TLS\t%s\n", groupDigits(conns.TLS))
		p("  Failed handshakes (443)\t%s\n", groupDigits(conns.HandshakeFailed))
		p("  Handshake avg\t%s\n", formatLatency(conns.AvgHandshake()))
		p("  Handshake max\t%s\n", formatLatency(conns.HandshakeMax))
		p("  First connection\t%s\n", formatTime(conns.First))
		p("  Last connection\t%s\n", formatTime(conns.Last))
		for _, t := range connRankedTables(conns) {
			pairs := t.counter.TopN(topN)
			if len(pairs) == 0 {
				continue
			}
			p("\n%s\n", t.title)
			p("  %s\tCONNECTIONS\n", t.keyHeader)
			for _, kv := range pairs {
				p("  %s\t%d\n", clean(kv.Key), kv.Count)
			}
		}
	}

	if meta.Narrowed {
		p("\nMATCHING REQUESTS (showing %d of %d)\n", len(res.Matches), res.MatchedRecords)
		if len(res.Matches) > 0 {
			p("  TIME\tLB\tCLIENT\tTARGET\tELB\tTGT\tLATENCY\tRX\tTX\tMETHOD\tHOST\tPATH\tUSER AGENT\tTLS\tCIPHER\tACTION\tERROR\n")
			for _, e := range res.Matches {
				p("  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					formatTime(e.Time), clean(e.LB), clean(e.ClientIP), dashIfEmpty(clean(e.Target)),
					dashIfEmpty(e.ELBStatus), dashIfEmpty(e.TargetStatus), formatLatency(e.Latency),
					e.ReceivedBytes, e.SentBytes, dashIfEmpty(clean(e.Method)),
					dashIfEmpty(clean(e.HostOrSNI())), truncate(dashIfEmpty(clean(e.Path)), pathWidth),
					truncate(dashIfEmpty(clean(e.UserAgent)), userAgentWidth),
					dashIfEmpty(clean(e.SSLProtocol)), dashIfEmpty(clean(e.SSLCipher)),
					dashIfEmpty(clean(e.Actions)), dashIfEmpty(clean(e.ErrorReason)))
			}
		}
		if len(res.ConnMatches) > 0 {
			p("\nMATCHING CONNECTIONS (showing %d of %d)\n", len(res.ConnMatches), res.MatchedConns)
			p("  TIME\tLB\tCLIENT\tLISTENER\tTLS\tCIPHER\tKEY EXCHANGE\tHANDSHAKE\tVERIFY\tCONN TRACE ID\n")
			for _, e := range res.ConnMatches {
				proto := dashIfEmpty(clean(e.SSLProtocol))
				if e.HandshakeFailed() {
					proto = "FAILED"
				}
				p("  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					formatTime(e.Time), clean(e.LB), clean(e.ClientIP), dashIfEmpty(e.Listener), proto,
					dashIfEmpty(clean(e.SSLCipher)), dashIfEmpty(clean(e.TLSKeyExchange)),
					formatLatency(e.TLSHandshakeTime), dashIfEmpty(clean(e.TLSVerifyStatus)),
					dashIfEmpty(clean(e.ConnTraceID)))
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

type elbHTMLView struct {
	Meta              Meta
	Res               engine.ELBResult
	Summary           *stats.ELBSummary
	Since, Until      string
	Days              int
	Elapsed           string
	Generated         string
	DistinctClientIPs int
	Tables            []htmlTable
	Hours             []bar
	Matches           []elblog.Entry
	// Conns is never nil so the template can read its fields directly.
	Conns                 *stats.ConnSummary
	ConnTables            []htmlTable
	ConnMatches           []elblog.Entry
	DistinctConnClientIPs int
	// HourPeak is the busiest UTC hour, used to label the hourly chart.
	HourPeak        bar
	WeakTLSRequests int
	WeakTLSConns    int

	// Health and timeline sections.
	Gauges              []gauge
	Charts              []chartView
	Donuts              []donut
	Groups              []groupRow
	Paths               []pathRow
	ErrReqs, WarnReqs   []elblog.Entry
	ErrTotal, WarnTotal int
}

// ELBHTML writes the self-contained load balancer report.
func ELBHTML(w io.Writer, res engine.ELBResult, meta Meta, topN int) error {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewELBSummary()
	}
	v := elbHTMLView{
		Meta:              meta,
		Res:               res,
		Summary:           sum,
		Since:             meta.Since.Format(dayLayout),
		Until:             meta.Until.Format(dayLayout),
		Days:              meta.Days(),
		Elapsed:           formatElapsed(res.Elapsed),
		Generated:         formatTime(meta.GeneratedAt),
		DistinctClientIPs: len(sum.ByClientIP),
		Hours:             hourBars(sum.ByHour),
		Matches:           res.Matches,
		Conns:             res.Conns,
		ConnMatches:       res.ConnMatches,
	}
	if v.Conns == nil {
		v.Conns = stats.NewConnSummary()
	}
	v.DistinctConnClientIPs = len(v.Conns.ByClientIP)
	v.WeakTLSRequests = weakTLS(sum.BySSLProtocol)
	v.WeakTLSConns = weakTLS(v.Conns.ByProtocol)
	for _, h := range v.Hours {
		if h.Count > v.HourPeak.Count {
			v.HourPeak = h
		}
	}
	for _, t := range connRankedTables(v.Conns) {
		pairs := t.counter.TopN(topN)
		if len(pairs) == 0 {
			continue
		}
		v.ConnTables = append(v.ConnTables, htmlTable{Title: t.htmlTitle, KeyHeader: t.htmlKey, Rows: bars(pairs)})
	}
	for _, t := range elbRankedTables(sum) {
		pairs := t.counter.TopN(topN)
		if len(pairs) == 0 {
			continue
		}
		v.Tables = append(v.Tables, htmlTable{Title: t.htmlTitle, KeyHeader: t.htmlKey, Rows: bars(pairs)})
	}
	if sum.Total > 0 {
		v.Gauges = healthGauges(sum)
		v.Charts = chartViews(elbCharts(sum))
		for _, d := range []donut{
			counterDonut("ELB status", statusClassCounter(sum.ByStatus), classTone),
			counterDonut("Load balancer", sum.ByLB, nil),
			counterDonut("Method", sum.ByMethod, nil),
			counterDonut("Listener type", sum.ByType, nil),
		} {
			if len(d.Slices) > 0 {
				v.Donuts = append(v.Donuts, d)
			}
		}
		v.Groups = groupRows(sum, topN)
		v.Paths = pathRows(sum, topN)
	}
	v.ErrReqs, v.WarnReqs, v.ErrTotal, v.WarnTotal = failing(res.Matches)
	return elbTemplate.Execute(w, v)
}

// humanBytes renders a byte count with a binary unit, e.g. "3.8 KiB".
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// formatLatency renders seconds as milliseconds, or "-" when unknown (< 0).
func formatLatency(sec float64) string {
	if sec < 0 {
		return "-"
	}
	ms := sec * 1000
	if ms < 10 {
		return fmt.Sprintf("%.1f ms", ms)
	}
	if ms < 10000 {
		return fmt.Sprintf("%.0f ms", ms)
	}
	return fmt.Sprintf("%.1f s", sec)
}

func dashIfEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
