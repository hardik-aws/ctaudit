package report

import (
	"io"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// ELBPDF writes the printable load balancer report: traffic totals, the
// hourly chart, the ranked tables, and the TLS connection summary. The
// per-request and per-connection tables are left to the HTML report.
func ELBPDF(w io.Writer, res engine.ELBResult, meta Meta, topN int) error {
	d, err := renderELBPDF(res, meta, topN)
	if err != nil {
		return err
	}
	return d.writeTo(w)
}

func renderELBPDF(res engine.ELBResult, meta Meta, topN int) (*pdfDoc, error) {
	sum := res.Summary
	if sum == nil {
		sum = stats.NewELBSummary()
	}
	conns := res.Conns
	if conns == nil {
		conns = stats.NewConnSummary()
	}

	d, err := newReportPDF("ELB Access Logs", meta)
	if err != nil {
		return nil, err
	}

	d.heading("Traffic")
	d.kv([][2]string{
		{"Objects scanned", groupDigits(res.ObjectsScanned)},
		{"Requests read", groupDigits(res.RecordsRead)},
		{"Matched requests", groupDigits(res.MatchedRecords)},
		{"Distinct client IPs", groupDigits(len(sum.ByClientIP))},
		{"Received", humanBytes(sum.ReceivedBytes)},
		{"Sent", humanBytes(sum.SentBytes)},
		{"4xx / 5xx", groupDigits(sum.Errors4xx) + " / " + groupDigits(sum.Errors5xx)},
		{"Latency avg / max", formatLatency(sum.AvgLatency()) + " / " + formatLatency(sum.LatencyMax)},
		{"Weak TLS requests", groupDigits(weakTLS(sum.BySSLProtocol))},
		{"First request", formatTime(sum.First)},
		{"Last request", formatTime(sum.Last)},
		{"Elapsed", formatElapsed(res.Elapsed)},
	})

	if sum.Total == 0 && conns.Total == 0 {
		d.note("No matching records")
		d.gap()
	}

	if sum.Total > 0 {
		d.hours(hourBars(sum.ByHour), "Requests by hour (UTC)")
		for _, t := range elbRankedTables(sum) {
			if pairs := t.counter.TopN(topN); len(pairs) > 0 {
				d.table(rankedPDFTable(t.htmlTitle, t.htmlKey, "Requests", pairs, sum.Total))
			}
		}
	}

	if conns.Total > 0 {
		d.heading("TLS connections")
		d.kv([][2]string{
			{"Connections read", groupDigits(res.ConnsRead)},
			{"Matched connections", groupDigits(res.MatchedConns)},
			{"TLS connections", groupDigits(conns.TLS)},
			{"Distinct client IPs", groupDigits(len(conns.ByClientIP))},
			{"Failed handshakes (443)", groupDigits(conns.HandshakeFailed)},
			{"Weak TLS connections", groupDigits(weakTLS(conns.ByProtocol))},
			{"Handshake avg / max", formatLatency(conns.AvgHandshake()) + " / " + formatLatency(conns.HandshakeMax)},
		})
		for _, t := range connRankedTables(conns) {
			if pairs := t.counter.TopN(topN); len(pairs) > 0 {
				d.table(rankedPDFTable(t.htmlTitle, t.htmlKey, "Connections", pairs, conns.Total))
			}
		}
	}

	d.errorList(res.Errors)
	return d, d.err
}
