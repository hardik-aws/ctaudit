package report

import (
	_ "embed"
	"html/template"
	"io"
	"strconv"
	"strings"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

//go:embed templates/report.html.tmpl
var reportTemplate string

// styleSheet is shared by the CloudTrail and ELB reports so they look alike.
//
//go:embed templates/style.css
var styleSheet string

// baseFuncs are the template helpers every report uses.
func baseFuncs() template.FuncMap {
	return template.FuncMap{
		"css":  func() template.CSS { return template.CSS(styleSheet) },
		"num":  groupDigits,
		"ts":   formatTime,
		"join": func(s []string) string { return strings.Join(s, ", ") },
	}
}

var htmlTemplate = template.Must(template.New("report").Funcs(baseFuncs()).Funcs(template.FuncMap{
	"sev": func(s findings.Severity) string { return strings.ToLower(s.String()) },
}).Parse(reportTemplate))

// bar is one row of a ranked table or one hour bucket. Pct is the row's
// count as a percentage of the largest row, used as a CSS width or height.
type bar struct {
	Key   string
	Count int
	Pct   int
}

type htmlTable struct {
	Title     string
	KeyHeader string
	Rows      []bar
}

// htmlView is everything the template reads. Keeping formatting decisions
// here rather than in the template keeps the template free of logic.
type htmlView struct {
	Meta               Meta
	Res                engine.Result
	Summary            *stats.Summary
	Since, Until       string
	Days               int
	Elapsed            string
	Generated          string
	DistinctPrincipals int
	DistinctSourceIPs  int
	Tables             []htmlTable
	Hours              []bar
}

// HTML writes the self-contained report: inline CSS, no scripts, no external
// assets. html/template escapes every record-derived string.
func HTML(w io.Writer, res engine.Result, meta Meta, topN int) error {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewSummary()
	}

	v := htmlView{
		Meta:               meta,
		Res:                res,
		Summary:            sum,
		Since:              meta.Since.Format(dayLayout),
		Until:              meta.Until.Format(dayLayout),
		Days:               meta.Days(),
		Elapsed:            formatElapsed(res.Elapsed),
		Generated:          formatTime(meta.GeneratedAt),
		DistinctPrincipals: len(sum.ByPrincipal),
		DistinctSourceIPs:  len(sum.BySourceIP),
	}
	for _, t := range rankedTables(sum) {
		pairs := t.counter.TopN(topN)
		if len(pairs) == 0 {
			continue
		}
		v.Tables = append(v.Tables, htmlTable{
			Title:     t.htmlTitle,
			KeyHeader: t.htmlKey,
			Rows:      bars(pairs),
		})
	}

	v.Hours = hourBars(sum.ByHour)

	return htmlTemplate.Execute(w, v)
}

func bars(pairs []stats.Pair) []bar {
	max := 0
	for _, p := range pairs {
		if p.Count > max {
			max = p.Count
		}
	}
	out := make([]bar, len(pairs))
	for i, p := range pairs {
		pct := 0
		if max > 0 {
			pct = p.Count * 100 / max
			if pct == 0 && p.Count > 0 {
				pct = 1
			}
		}
		out[i] = bar{Key: p.Key, Count: p.Count, Pct: pct}
	}
	return out
}

// hourBars turns an hour-of-day counter into 24 bars labelled 00..23.
func hourBars(byHour stats.Counter) []bar {
	hours := make([]stats.Pair, 24)
	for h := range hours {
		hours[h] = stats.Pair{Key: strconv.Itoa(h), Count: byHour[strconv.Itoa(h)]}
	}
	out := bars(hours)
	for i := range out {
		out[i].Key = twoDigits(i)
	}
	return out
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
