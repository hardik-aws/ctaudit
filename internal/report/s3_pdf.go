package report

import (
	"fmt"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// renderS3PDF mirrors renderWAFPDF: the traffic summary, the findings, the
// hourly chart, and the ranked tables. Matching requests are left to the
// HTML report, mirroring ELBPDF and WAFPDF.
func renderS3PDF(res engine.S3Result, meta Meta, topN int) (*pdfDoc, error) {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewS3Summary()
	}

	d, err := newReportPDF("Amazon S3 Access Logs", meta)
	if err != nil {
		return nil, err
	}

	d.heading("Traffic")
	d.kv([][2]string{
		{"Layout", dashIfEmpty(res.Layout)},
		{"Source buckets", groupDigits(len(res.SourceBuckets))},
		{"Objects scanned", groupDigits(res.ObjectsScanned)},
		{"Records read", groupDigits(res.RecordsRead)},
		{"Matched records", groupDigits(res.MatchedRecords)},
		{"Requests", groupDigits(sum.Total)},
		{"Errors", groupDigits(sum.Errors)},
		{"Denied", groupDigits(sum.Denied)},
		{"Anonymous", groupDigits(sum.Anonymous)},
		{"Bytes sent", humanBytes(sum.BytesSent)},
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
				{Header: "Severity", Width: 0.10},
				{Header: "Rule", Width: 0.16},
				{Header: "Actor", Width: 0.20},
				{Header: "Detail", Width: 0.44},
				{Header: "Time", Width: 0.10},
			},
		}
		for _, f := range res.Findings {
			tbl.Rows = append(tbl.Rows, []string{
				f.Severity.String(), f.Rule, f.Actor, f.Title + " — " + f.Detail, formatTime(f.Time),
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
		d.hours(actionBarsToBars(wafHourBars(sum.ByHour)), "Requests per hour (UTC)")
		for _, t := range s3RankedTables(sum) {
			pairs := t.counter.TopN(topN)
			if len(pairs) == 0 {
				continue
			}
			if s3ByteTableTitles[t.title] {
				d.table(bytesPDFTable(t.htmlTitle, t.htmlKey, pairs))
			} else {
				d.table(rankedPDFTable(t.htmlTitle, t.htmlKey, "Requests", pairs, sum.Total))
			}
		}
	}

	d.errorList(res.Errors)
	return d, d.err
}

// bytesPDFTable is rankedPDFTable's counterpart for the two byte-count
// tables: it formats the count column with humanBytes instead of
// groupDigits, and leaves out the percentage column since the total is a
// request count, not a byte count.
func bytesPDFTable(title, keyHeader string, pairs []stats.Pair) pdfTable {
	t := pdfTable{
		Title: title,
		Columns: []pdfColumn{
			{Header: keyHeader, Width: 0.75},
			{Header: "Bytes", Width: 0.25, Right: true},
		},
	}
	for _, p := range pairs {
		t.Rows = append(t.Rows, []string{p.Key, humanBytes(int64(p.Count))})
	}
	return t
}
