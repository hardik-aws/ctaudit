package report

import (
	"fmt"
	"io"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// WAFPDF writes the printable WAF log report: the traffic summary, the
// findings, the hourly chart, and the ranked tables. Matching requests are
// left to the HTML report, mirroring ELBPDF.
func WAFPDF(w io.Writer, res engine.WAFResult, meta Meta, topN int) error {
	d, err := renderWAFPDF(res, meta, topN)
	if err != nil {
		return err
	}
	return d.writeTo(w)
}

func renderWAFPDF(res engine.WAFResult, meta Meta, topN int) (*pdfDoc, error) {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewWAFSummary()
	}

	d, err := newReportPDF("AWS WAF Logs", meta)
	if err != nil {
		return nil, err
	}

	d.heading("Traffic")
	d.kv([][2]string{
		{"Objects scanned", groupDigits(res.ObjectsScanned)},
		{"Records read", groupDigits(res.RecordsRead)},
		{"Matched records", groupDigits(res.MatchedRecords)},
		{"Web ACLs", groupDigits(len(res.WebACLs))},
		{"Requests", groupDigits(sum.Total)},
		{"Blocked", groupDigits(sum.Blocked())},
		{"Allowed", groupDigits(sum.ByAction["ALLOW"])},
		{"Counted", groupDigits(sum.ByAction["COUNT"])},
		{"Challenged", groupDigits(sum.ByAction["CAPTCHA"] + sum.ByAction["CHALLENGE"])},
		{"Block rate", fmt.Sprintf("%.1f%%", sum.BlockRate()*100)},
		{"First request", formatTime(sum.First)},
		{"Last request", formatTime(sum.Last)},
		{"Elapsed", formatElapsed(res.Elapsed)},
	})

	// The engine already keeps CRITICAL findings past the cap, so every
	// finding in res.Findings is drawn.
	title := fmt.Sprintf("Findings (%d)", len(res.Findings))
	if len(res.Findings) == 0 {
		d.heading(title)
		d.note("No findings")
		d.gap()
	} else {
		tbl := pdfTable{
			Title: title,
			Columns: []pdfColumn{
				{Header: "Severity", Width: 0.11},
				{Header: "Rule", Width: 0.16},
				{Header: "Title", Width: 0.20},
				{Header: "Client or rule", Width: 0.18},
				{Header: "Detail", Width: 0.25},
				{Header: "Time", Width: 0.10},
			},
		}
		for _, f := range res.Findings {
			tbl.Rows = append(tbl.Rows, []string{
				f.Severity.String(), f.Rule, f.Title, f.Actor, f.Detail, formatTime(f.Time),
			})
		}
		d.table(tbl)
	}
	if res.FindingsDropped > 0 {
		d.note(fmt.Sprintf("%d more findings not shown", res.FindingsDropped))
		d.gap()
	}

	if sum.Total == 0 {
		d.note("No matching records")
		d.gap()
	} else {
		d.hours(actionBarsToBars(wafHourBars(sum.ByHour)), "Actions by hour (UTC)")
		for _, t := range wafRankedTables(sum) {
			if pairs := t.counter.TopN(topN); len(pairs) > 0 {
				d.table(rankedPDFTable(t.htmlTitle, t.htmlKey, "Requests", pairs, sum.Total))
			}
		}
	}

	d.errorList(res.Errors)
	return d, d.err
}
