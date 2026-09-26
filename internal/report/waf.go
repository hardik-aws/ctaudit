package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/stats"
	"github.com/gsmappdev/ctaudit/internal/waflog"
)

//go:embed templates/waf.html.tmpl
var wafTemplateText string

var wafTemplate = template.Must(template.New("waf").Funcs(baseFuncs()).Funcs(template.FuncMap{
	"elbcss":  func() template.CSS { return template.CSS(elbStyleSheet) },
	"elbjs":   func() template.JS { return template.JS(elbScript) },
	"tone":    tone,
	"dash":    dashIfEmpty,
	"sevtone": sevTone,
	"pctf":    func(v float64) string { return fmt.Sprintf("%.1f%%", v) },
}).Parse(wafTemplateText))

// sevTone maps a finding severity to the elb.css pill classes, since the WAF
// report reuses that stylesheet rather than the CloudTrail report's badges.
func sevTone(s findings.Severity) string {
	switch s {
	case findings.SevCritical, findings.SevHigh:
		return "crit"
	case findings.SevMedium:
		return "warn"
	default:
		return "info"
	}
}

// wafRankedTables lists the WAF counters in report order. Both renderers
// use it so the terminal and HTML reports agree.
func wafRankedTables(s *stats.WAFSummary) []rankedTable {
	return []rankedTable{
		{"WEB ACLS", "WEB ACL", "Web ACLs", "Web ACL", s.ByACL},
		{"TERMINATING RULES", "RULE", "Terminating rules", "Rule", s.ByRule},
		{"RULE GROUPS", "RULE GROUP", "Rule groups", "Rule group", s.ByRuleGroup},
		{"TOP BLOCKED CLIENT IPS", "CLIENT IP", "Top blocked client IPs", "Client IP", s.ByBlockedIP},
		{"TOP CLIENT IPS", "CLIENT IP", "Top client IPs", "Client IP", s.ByClientIP},
		{"BLOCKED COUNTRIES", "COUNTRY", "Blocked countries", "Country", s.ByBlockedCountry},
		{"COUNTRIES", "COUNTRY", "Countries", "Country", s.ByCountry},
		{"HOSTS", "HOST", "Hosts", "Host", s.ByHost},
		{"URIS, NUMBERS AS {N}", "URI", "URIs, numbers as {n}", "URI", s.ByURI},
		{"METHODS", "METHOD", "Methods", "Method", s.ByMethod},
		{"USER AGENTS", "USER AGENT", "User agents", "User agent", s.ByUserAgent},
		{"SOURCES", "SOURCE", "Sources", "Source", s.BySource},
		{"LABELS", "LABEL", "Labels", "Label", s.ByLabel},
		{"COUNT RULES", "RULE", "COUNT rules", "Rule", s.ByCountRule},
		{"JA4 FINGERPRINTS", "JA4", "JA4 fingerprints", "JA4", s.ByJA4},
		{"RESPONSE CODES", "RESPONSE CODE", "Response codes", "Response code", s.ByResponseCode},
	}
}

// wafTerminalTables is how many of wafRankedTables the terminal report
// prints; the rest are left to the HTML and PDF reports' breakdown section.
const wafTerminalTables = 6

// actionBar is one hourly bar split by action; Title carries the per-action
// breakdown for the HTML tooltip.
type actionBar struct {
	bar
	Title string
}

// wafHourBars turns the per-hour action counters into bars sorted by hour,
// one per hour the scan saw traffic. The bar height is the hour's total
// requests; Title lists the per-action split.
func wafHourBars(byHour map[int64]stats.Counter) []actionBar {
	if len(byHour) == 0 {
		return nil
	}
	hours := make([]int64, 0, len(byHour))
	for h := range byHour {
		hours = append(hours, h)
	}
	sort.Slice(hours, func(i, j int) bool { return hours[i] < hours[j] })

	pairs := make([]stats.Pair, len(hours))
	for i, h := range hours {
		total := 0
		for _, n := range byHour[h] {
			total += n
		}
		pairs[i] = stats.Pair{Key: time.Unix(h*3600, 0).UTC().Format("2006-01-02 15:00"), Count: total}
	}
	bs := bars(pairs)

	out := make([]actionBar, len(bs))
	for i, b := range bs {
		c := byHour[hours[i]]
		var parts []string
		for _, p := range c.TopN(len(c)) {
			parts = append(parts, fmt.Sprintf("%s %d", p.Key, p.Count))
		}
		out[i] = actionBar{bar: b, Title: strings.Join(parts, ", ")}
	}
	return out
}

// actionBarsToBars strips the per-action title, for renderers (the PDF's
// hour chart) that only draw the bar itself.
func actionBarsToBars(in []actionBar) []bar {
	out := make([]bar, len(in))
	for i, a := range in {
		out[i] = a.bar
	}
	return out
}

// WAFTerminal writes the plain-text WAF log report.
func WAFTerminal(w io.Writer, res engine.WAFResult, meta Meta, topN int) error {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewWAFSummary()
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	p := func(format string, a ...any) { fmt.Fprintf(tw, format, a...) }

	p("AWS WAF Logs — %s .. %s (%d days)\n",
		meta.Since.Format(dayLayout), meta.Until.Format(dayLayout), meta.Days())
	p("Bucket: %s   Accounts: %d   Regions: %d\n", clean(meta.Bucket), len(meta.Accounts), len(meta.Regions))
	p("Objects scanned: %s   Records read: %s   Matched: %s   Web ACLs: %s   Elapsed: %s\n",
		groupDigits(res.ObjectsScanned), groupDigits(res.RecordsRead),
		groupDigits(res.MatchedRecords), groupDigits(len(res.WebACLs)), formatElapsed(res.Elapsed))

	p("\nTRAFFIC\n")
	p("  Requests\t%s\n", groupDigits(sum.Total))
	p("  Blocked\t%s\n", groupDigits(sum.Blocked()))
	p("  Allowed\t%s\n", groupDigits(sum.ByAction["ALLOW"]))
	p("  Counted\t%s\n", groupDigits(sum.Counted))
	p("  Challenged\t%s\n", groupDigits(sum.ByAction["CAPTCHA"]+sum.ByAction["CHALLENGE"]))
	p("  Block rate\t%.1f%%\n", sum.BlockRate()*100)
	p("  First request\t%s\n", formatTime(sum.First))
	p("  Last request\t%s\n", formatTime(sum.Last))

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

	for _, t := range wafRankedTables(sum)[:wafTerminalTables] {
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
			p("  TIME\tWEB ACL\tACTION\tRULE\tCLIENT IP\tCOUNTRY\tMETHOD\tHOST\tURI\tUSER AGENT\n")
			for _, e := range res.Matches {
				p("  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					formatTime(e.Time), dashIfEmpty(clean(e.WebACL)), e.Action, dashIfEmpty(clean(e.Rule)),
					clean(e.ClientIP), dashIfEmpty(clean(e.Country)), dashIfEmpty(clean(e.Method)),
					dashIfEmpty(clean(e.Host)), truncate(dashIfEmpty(clean(e.URI)), pathWidth),
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

// wafHTMLView is everything the WAF HTML template reads.
type wafHTMLView struct {
	Meta              Meta
	Res               engine.WAFResult
	Summary           *stats.WAFSummary
	Since, Until      string
	Days              int
	Elapsed           string
	Generated         string
	DistinctClientIPs int
	WebACLCount       int
	Challenged        int
	BlockRate         string
	Tables            []htmlTable
	Hours             []actionBar
	Matches           []waflog.Entry
}

// WAFHTML writes the self-contained WAF log report.
func WAFHTML(w io.Writer, res engine.WAFResult, meta Meta, topN int) error {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewWAFSummary()
	}
	v := wafHTMLView{
		Meta:              meta,
		Res:               res,
		Summary:           sum,
		Since:             meta.Since.Format(dayLayout),
		Until:             meta.Until.Format(dayLayout),
		Days:              meta.Days(),
		Elapsed:           formatElapsed(res.Elapsed),
		Generated:         formatTime(meta.GeneratedAt),
		DistinctClientIPs: len(sum.ByClientIP),
		WebACLCount:       len(res.WebACLs),
		Challenged:        sum.ByAction["CAPTCHA"] + sum.ByAction["CHALLENGE"],
		BlockRate:         fmt.Sprintf("%.1f%%", sum.BlockRate()*100),
		Hours:             wafHourBars(sum.ByHour),
		Matches:           res.Matches,
	}
	for _, t := range wafRankedTables(sum) {
		pairs := t.counter.TopN(topN)
		if len(pairs) == 0 {
			continue
		}
		v.Tables = append(v.Tables, htmlTable{Title: t.htmlTitle, KeyHeader: t.htmlKey, Rows: bars(pairs)})
	}
	return wafTemplate.Execute(w, v)
}
