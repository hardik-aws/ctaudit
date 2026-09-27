package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"net/netip"
	"strconv"
	"text/tabwriter"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/flowlog"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

//go:embed templates/vpc.html.tmpl
var vpcTemplateText string

var vpcTemplate = template.Must(template.New("vpc").Funcs(baseFuncs()).Funcs(template.FuncMap{
	"elbcss":  func() template.CSS { return template.CSS(elbStyleSheet) },
	"elbjs":   func() template.JS { return template.JS(elbScript) },
	"tone":    tone,
	"atone":   actionTone,
	"dash":    dashIfEmpty,
	"sevtone": sevTone,
	"bytes":   humanBytes,
	"bytesn":  func(n int) string { return humanBytes(int64(n)) },
	"num64":   func(n int64) string { return groupDigits(int(n)) },
	"port":    portText,
	"addr":    addrText,
}).Parse(vpcTemplateText))

func portText(p int) string {
	if p < 0 {
		return "-"
	}
	return strconv.Itoa(p)
}

func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.String()
}

// actionTone is tone, but only for the two flow actions. A ranked table's
// key can be a protocol number, a port, or any other short string, and
// tone's 3-digit rule is meant for HTTP-like status codes; applying it to
// every ranked key would paint an unrelated 3-digit value (a protocol
// number, say) with a status-code color by coincidence. Only ACCEPT and
// REJECT get a pill; everything else renders plain.
func actionTone(v string) string {
	if v == "ACCEPT" || v == "REJECT" {
		return tone(v)
	}
	return ""
}

// vpcTable is a ranked table whose values are flow counts, or byte counts
// when bytes is set.
type vpcTable struct {
	rankedTable
	bytes bool
}

// vpcRankedTables lists the VPC counters in report order; every renderer
// uses it so the reports agree.
func vpcRankedTables(s *stats.VPCSummary) []vpcTable {
	return []vpcTable{
		{rankedTable{"ACTIONS", "ACTION", "Actions", "Action", s.ByAction}, false},
		{rankedTable{"BYTES BY ACTION", "ACTION", "Bytes by action", "Action", s.BytesByAction}, true},
		{rankedTable{"DESTINATION PORTS", "SERVICE", "Destination ports", "Service", s.ByDstPort}, false},
		{rankedTable{"TOP SOURCES", "SOURCE", "Top sources", "Source", s.BySrc}, false},
		{rankedTable{"TOP DESTINATIONS", "DESTINATION", "Top destinations", "Destination", s.ByDst}, false},
		{rankedTable{"TOP PAIRS BY BYTES", "SOURCE -> DESTINATION", "Top pairs by bytes", "Source -> destination", s.PairBytes}, true},
		{rankedTable{"REJECTED FLOWS BY SOURCE", "SOURCE", "Rejected flows by source", "Source", s.RejectsBySrc}, false},
		{rankedTable{"PROTOCOLS", "PROTOCOL", "Protocols", "Protocol", s.ByProtocol}, false},
		{rankedTable{"INTERFACES", "INTERFACE", "Interfaces", "Interface", s.ByInterface}, false},
		{rankedTable{"FLOW DIRECTIONS", "DIRECTION", "Flow directions", "Direction", s.ByDirection}, false},
	}
}

// vpcTerminalTables is how many of vpcRankedTables the terminal prints.
const vpcTerminalTables = 7

// vpcNotes lists the data-quality warnings every report shows.
func vpcNotes(s *stats.VPCSummary) []string {
	var out []string
	if s.SkipData > 0 {
		out = append(out, fmt.Sprintf("%s SKIPDATA rows: flow log capture skipped records in those intervals, so totals undercount the real traffic.", groupDigits(s.SkipData)))
	}
	if s.Truncated() {
		out = append(out, "Findings may be incomplete: a bounded tracker reached its limit (too many distinct sources or exposed services). Narrow the scan with --src-cidr, --dst-cidr, --interfaces, or --vpcs.")
	}
	return out
}

func vpcSummaryOrEmpty(res engine.VPCResult) *stats.VPCSummary {
	if res.Summary != nil {
		return res.Summary
	}
	return stats.NewVPCSummary(stats.VPCLimits{})
}

// VPCTerminal writes the plain-text VPC Flow Logs report.
func VPCTerminal(w io.Writer, res engine.VPCResult, meta Meta, topN int) error {
	sum := vpcSummaryOrEmpty(res)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	p := func(format string, a ...any) { fmt.Fprintf(tw, format, a...) }

	p("VPC Flow Logs — %s .. %s (%d days)\n", meta.Since.Format(dayLayout), meta.Until.Format(dayLayout), meta.Days())
	p("Bucket: %s   Accounts: %d   Regions: %d\n", clean(meta.Bucket), len(meta.Accounts), len(meta.Regions))
	p("Objects scanned: %s   Records read: %s   Matched: %s   Elapsed: %s\n",
		groupDigits(res.ObjectsScanned), groupDigits(res.RecordsRead), groupDigits(res.MatchedRecords), formatElapsed(res.Elapsed))

	p("\nTRAFFIC\n")
	p("  Flows\t%s\n", groupDigits(sum.Flows))
	p("  Bytes\t%s\n", humanBytes(sum.Bytes))
	p("  Packets\t%s\n", groupDigits(int(sum.Packets)))
	p("  Accepted\t%s\n", groupDigits(sum.Accepted()))
	p("  Rejected\t%s\n", groupDigits(sum.Rejected()))
	p("  Reject rate\t%.1f%%\n", sum.RejectRate()*100)
	p("  Interfaces\t%s\n", groupDigits(len(sum.ByInterface)))
	p("  NODATA rows\t%s\n", groupDigits(sum.NoData))
	p("  SKIPDATA rows\t%s\n", groupDigits(sum.SkipData))
	p("  First flow\t%s\n", formatTime(sum.First))
	p("  Last flow\t%s\n", formatTime(sum.Last))
	for _, n := range vpcNotes(sum) {
		p("  Note: %s\n", n)
	}

	p("\nFINDINGS (%d)\n", len(res.Findings))
	if len(res.Findings) == 0 {
		p("  none\n")
	}
	for _, f := range res.Findings {
		p("  [%s] %s — %s: %s\n", f.Severity, clean(f.Title), clean(f.Actor), clean(f.Detail))
	}
	if res.FindingsDropped > 0 {
		p("  (%d further findings dropped at the cap)\n", res.FindingsDropped)
	}

	for _, t := range vpcRankedTables(sum)[:vpcTerminalTables] {
		pairs := t.counter.TopN(topN)
		if len(pairs) == 0 {
			continue
		}
		p("\n%s\n", t.title)
		if t.bytes {
			p("  %s\tBYTES\n", t.keyHeader)
		} else {
			p("  %s\tFLOWS\n", t.keyHeader)
		}
		for _, kv := range pairs {
			v := groupDigits(kv.Count)
			if t.bytes {
				v = humanBytes(int64(kv.Count))
			}
			p("  %s\t%s\n", clean(kv.Key), v)
		}
	}

	if meta.Narrowed {
		p("\nMATCHING FLOWS (showing %d of %d)\n", len(res.Matches), res.MatchedRecords)
		if len(res.Matches) > 0 {
			p("  START\tINTERFACE\tACTION\tSOURCE\tSPORT\tDESTINATION\tDPORT\tPROTO\tPACKETS\tBYTES\tDIRECTION\tVPC\n")
			for _, e := range res.Matches {
				p("  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					formatTime(e.Start), dashIfEmpty(clean(e.InterfaceID)), dashIfEmpty(clean(e.Action)),
					addrText(e.Source()), portText(e.SrcPort), addrText(e.Dest()), portText(e.DstPort),
					dashIfEmpty(e.ProtocolName()), groupDigits(int(e.Packets)), humanBytes(e.Bytes),
					dashIfEmpty(clean(e.FlowDirection)), dashIfEmpty(clean(e.VPCID)))
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

// vpcHTMLTable is one breakdown table; Bytes switches the value column.
type vpcHTMLTable struct {
	Title     string
	KeyHeader string
	Bytes     bool
	Rows      []bar
}

// vpcHTMLView is everything the VPC HTML template reads.
type vpcHTMLView struct {
	Meta         Meta
	Res          engine.VPCResult
	Summary      *stats.VPCSummary
	Since, Until string
	Days         int
	Elapsed      string
	Generated    string
	Interfaces   int
	RejectRate   string
	Notes        []string
	Tables       []vpcHTMLTable
	Hours        []actionBar
	Matches      []flowlog.Entry
}

// VPCHTML writes the self-contained VPC Flow Logs report.
func VPCHTML(w io.Writer, res engine.VPCResult, meta Meta, topN int) error {
	sum := vpcSummaryOrEmpty(res)
	v := vpcHTMLView{
		Meta:       meta,
		Res:        res,
		Summary:    sum,
		Since:      meta.Since.Format(dayLayout),
		Until:      meta.Until.Format(dayLayout),
		Days:       meta.Days(),
		Elapsed:    formatElapsed(res.Elapsed),
		Generated:  formatTime(meta.GeneratedAt),
		Interfaces: len(sum.ByInterface),
		RejectRate: fmt.Sprintf("%.1f%%", sum.RejectRate()*100),
		Notes:      vpcNotes(sum),
		Hours:      wafHourBars(sum.ByHour),
		Matches:    res.Matches,
	}
	for _, t := range vpcRankedTables(sum) {
		if pairs := t.counter.TopN(topN); len(pairs) > 0 {
			v.Tables = append(v.Tables, vpcHTMLTable{Title: t.htmlTitle, KeyHeader: t.htmlKey, Bytes: t.bytes, Rows: bars(pairs)})
		}
	}
	return vpcTemplate.Execute(w, v)
}
