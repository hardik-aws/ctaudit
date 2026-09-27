package report

import (
	"fmt"
	"io"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// VPCPDF writes the printable VPC Flow Logs report: totals, data-quality
// notes, findings, the hourly chart, and the ranked tables. Matching flows
// are left to the HTML report, as for WAFPDF.
func VPCPDF(w io.Writer, res engine.VPCResult, meta Meta, topN int) error {
	d, err := renderVPCPDF(res, meta, topN)
	if err != nil {
		return err
	}
	return d.writeTo(w)
}

func renderVPCPDF(res engine.VPCResult, meta Meta, topN int) (*pdfDoc, error) {
	sum := vpcSummaryOrEmpty(res)
	d, err := newReportPDF("VPC Flow Logs", meta)
	if err != nil {
		return nil, err
	}

	d.heading("Traffic")
	d.kv([][2]string{
		{"Objects scanned", groupDigits(res.ObjectsScanned)},
		{"Records read", groupDigits(res.RecordsRead)},
		{"Matched flows", groupDigits(res.MatchedRecords)},
		{"Flows", groupDigits(sum.Flows)},
		{"Bytes", humanBytes(sum.Bytes)},
		{"Packets", groupDigits(int(sum.Packets))},
		{"Accepted", groupDigits(sum.Accepted())},
		{"Rejected", groupDigits(sum.Rejected())},
		{"Reject rate", fmt.Sprintf("%.1f%%", sum.RejectRate()*100)},
		{"Interfaces", groupDigits(len(sum.ByInterface))},
		{"NODATA / SKIPDATA rows", groupDigits(sum.NoData) + " / " + groupDigits(sum.SkipData)},
		{"First flow", formatTime(sum.First)},
		{"Last flow", formatTime(sum.Last)},
		{"Elapsed", formatElapsed(res.Elapsed)},
	})
	if notes := vpcNotes(sum); len(notes) > 0 {
		for _, n := range notes {
			d.note(n)
		}
		d.gap()
	}

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
				{Header: "Rule", Width: 0.17},
				{Header: "Title", Width: 0.19},
				{Header: "Host or source", Width: 0.16},
				{Header: "Detail", Width: 0.27},
				{Header: "Time", Width: 0.10},
			},
		}
		for _, f := range res.Findings {
			tbl.Rows = append(tbl.Rows, []string{f.Severity.String(), f.Rule, f.Title, f.Actor, f.Detail, formatTime(f.Time)})
		}
		d.table(tbl)
	}
	if res.FindingsDropped > 0 {
		d.note(fmt.Sprintf("%d more findings not shown", res.FindingsDropped))
		d.gap()
	}

	if sum.Flows == 0 {
		d.note("No matching flows")
		d.gap()
	} else {
		d.hours(actionBarsToBars(wafHourBars(sum.ByHour)), "Flows by hour (UTC)")
		for _, t := range vpcRankedTables(sum) {
			pairs := t.counter.TopN(topN)
			if len(pairs) == 0 {
				continue
			}
			if t.bytes {
				d.table(bytesPDFTable(t.htmlTitle, t.htmlKey, pairs, sum.Bytes))
			} else {
				d.table(rankedPDFTable(t.htmlTitle, t.htmlKey, "Flows", pairs, sum.Flows))
			}
		}
	}

	d.errorList(res.Errors)
	return d, d.err
}

// bytesPDFTable is rankedPDFTable for byte counts.
func bytesPDFTable(title, keyHeader string, pairs []stats.Pair, total int64) pdfTable {
	t := pdfTable{
		Title: title,
		Columns: []pdfColumn{
			{Header: keyHeader, Width: 0.70},
			{Header: "Bytes", Width: 0.18, Right: true},
			{Header: "%", Width: 0.12, Right: true},
		},
	}
	for _, p := range pairs {
		pct := ""
		if total > 0 {
			pct = fmt.Sprintf("%.1f", float64(p.Count)*100/float64(total))
		}
		t.Rows = append(t.Rows, []string{p.Key, humanBytes(int64(p.Count)), pct})
	}
	return t
}
