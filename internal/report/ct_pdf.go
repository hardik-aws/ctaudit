package report

import (
	"fmt"
	"io"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// PDF writes the printable CloudTrail report: the summary, the findings,
// the hourly chart, and the ranked tables. Matching events are left to the
// HTML report.
func PDF(w io.Writer, res engine.Result, meta Meta, topN int) error {
	d, err := renderPDF(res, meta, topN)
	if err != nil {
		return err
	}
	return d.writeTo(w)
}

func renderPDF(res engine.Result, meta Meta, topN int) (*pdfDoc, error) {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewSummary()
	}

	d, err := newReportPDF("CloudTrail Audit", meta)
	if err != nil {
		return nil, err
	}

	d.heading("Summary")
	d.kv([][2]string{
		{"Objects scanned", groupDigits(res.ObjectsScanned)},
		{"Records read", groupDigits(res.RecordsRead)},
		{"Matched records", groupDigits(res.MatchedRecords)},
		{"Total events", groupDigits(sum.TotalEvents)},
		{"Write events", groupDigits(sum.WriteEvents)},
		{"Error events", groupDigits(sum.ErrorEvents)},
		{"First event", formatTime(sum.FirstEvent)},
		{"Last event", formatTime(sum.LastEvent)},
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
				{Header: "Time", Width: 0.2},
				{Header: "Rule", Width: 0.17},
				{Header: "Actor", Width: 0.24},
				{Header: "Detail", Width: 0.28},
			},
		}
		for _, f := range res.Findings {
			tbl.Rows = append(tbl.Rows, []string{
				f.Severity.String(), formatTime(f.Time), f.Rule, f.Actor, f.Detail,
			})
		}
		d.table(tbl)
	}
	if res.DroppedFindings > 0 {
		d.note(fmt.Sprintf("%d more findings not shown", res.DroppedFindings))
		d.gap()
	}

	if sum.TotalEvents == 0 {
		d.note("No matching records")
		d.gap()
	} else {
		d.hours(hourBars(sum.ByHour), "Events by hour (UTC)")
		for _, t := range rankedTables(sum) {
			if pairs := t.counter.TopN(topN); len(pairs) > 0 {
				d.table(rankedPDFTable(t.htmlTitle, t.htmlKey, "Events", pairs, sum.TotalEvents))
			}
		}
	}

	d.errorList(res.Errors)
	return d, d.err
}
