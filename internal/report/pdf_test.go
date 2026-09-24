package report

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gsmappdev/ctaudit/internal/engine"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// renderPDFBytes writes d and checks the PDF envelope.
func renderPDFBytes(t *testing.T, d *pdfDoc) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := d.writeTo(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Errorf("PDF does not start with %%PDF-: %q", out[:min(len(out), 16)])
	}
	if !bytes.HasSuffix(bytes.TrimRight(out, "\r\n"), []byte("%%EOF")) {
		t.Errorf("PDF does not end with %%%%EOF")
	}
	return out
}

func drawnContains(d *pdfDoc, want string) bool {
	for _, s := range d.drawn {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

func countPages(out []byte) int {
	// "/Type /Pages" is the page tree; count only leaf page objects.
	return bytes.Count(out, []byte("/Type /Page\n")) + bytes.Count(out, []byte("/Type /Page ")) -
		bytes.Count(out, []byte("/Type /Pages "))
}

func TestPDFDocTablePaginates(t *testing.T) {
	pdfNoCompress = true
	defer func() { pdfNoCompress = false }()

	d, err := newPDFDoc("ctaudit · generated 2026-09-23T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	d.title("Test report", "subtitle")
	tbl := pdfTable{
		Title:   "Rows",
		Columns: []pdfColumn{{Header: "KeyColumn", Width: 0.8}, {Header: "Count", Width: 0.2, Right: true}},
	}
	for i := range 200 {
		tbl.Rows = append(tbl.Rows, []string{"row " + strconv.Itoa(i), strconv.Itoa(i)})
	}
	d.table(tbl)
	out := renderPDFBytes(t, d)

	pages := d.pdf.GetNumberOfPages()
	if pages < 2 {
		t.Fatalf("got %d pages, want more than 1", pages)
	}
	if n := countPages(out); n != pages {
		t.Errorf("counted %d page objects, gopdf reports %d", n, pages)
	}
	headers := 0
	for _, s := range d.drawn {
		if s == "KeyColumn" {
			headers++
		}
	}
	if headers != pages {
		t.Errorf("header drawn %d times over %d pages", headers, pages)
	}
	if !drawnContains(d, "row 199") {
		t.Error("last row missing")
	}
	if !drawnContains(d, "page 2 of "+strconv.Itoa(pages)) {
		t.Error("footer missing page numbers")
	}
}

func TestPDFDocFit(t *testing.T) {
	d, err := newPDFDoc("f")
	if err != nil {
		t.Fatal(err)
	}
	d.font(false, pdfBodySize, colText)
	long := strings.Repeat("ünïcødé\x1b[31m\t日本 ", 40)
	const width = 120.0
	got := d.fit(long, width)
	if !utf8.ValidString(got) {
		t.Fatalf("fit returned invalid UTF-8: %q", got)
	}
	if strings.ContainsAny(got, "\x1b\t") {
		t.Errorf("fit kept control characters: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("fit did not mark truncation: %q", got)
	}
	if w := d.width(got); w > width {
		t.Errorf("fitted width %.1f exceeds %.1f", w, width)
	}
	if short := d.fit("TLSv1.2", width); short != "TLSv1.2" {
		t.Errorf("fit changed a short string: %q", short)
	}
}

func TestRankedPDFTable(t *testing.T) {
	tbl := rankedPDFTable("Top", "Key", "Count", []stats.Pair{{Key: "a", Count: 3}, {Key: "b", Count: 1}}, 4)
	if len(tbl.Rows) != 2 || tbl.Rows[0][2] != "75.0" || tbl.Rows[1][1] != "1" {
		t.Errorf("unexpected rows: %v", tbl.Rows)
	}
}

func TestELBPDF(t *testing.T) {
	res, meta := sampleELBResult()
	d, err := renderELBPDF(res, meta, 10)
	if err != nil {
		t.Fatal(err)
	}
	renderPDFBytes(t, d)
	for _, want := range []string{
		"ELB Access Logs", "Traffic", "Requests by hour (UTC)", "By TLS cipher", "TLSv1.2",
		"TLS connections", "198.18.71.40", "Errors (1)",
	} {
		if !drawnContains(d, want) {
			t.Errorf("ELB PDF missing %q", want)
		}
	}
	if drawnContains(d, "No matching records") {
		t.Error("non-empty ELB PDF says no matching records")
	}

	var buf bytes.Buffer
	if err := ELBPDF(&buf, res, meta, 10); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Error("ELBPDF output is not a PDF")
	}
}

func TestELBPDFEmpty(t *testing.T) {
	d, err := renderELBPDF(engine.ELBResult{}, Meta{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	renderPDFBytes(t, d)
	if !drawnContains(d, "No matching records") {
		t.Error("empty ELB PDF missing the empty-state note")
	}
}

func TestPDFErrorListCap(t *testing.T) {
	d, err := newPDFDoc("f")
	if err != nil {
		t.Fatal(err)
	}
	errs := make([]string, pdfMaxErrors+5)
	for i := range errs {
		errs[i] = "err " + strconv.Itoa(i)
	}
	d.errorList(errs)
	renderPDFBytes(t, d)
	if drawnContains(d, "err "+strconv.Itoa(pdfMaxErrors)) {
		t.Error("error list exceeded the cap")
	}
	if !drawnContains(d, "and 5 more") {
		t.Error("error list missing the overflow line")
	}
}

func TestCloudTrailPDF(t *testing.T) {
	d, err := renderPDF(sampleResult(), sampleMeta(), 10)
	if err != nil {
		t.Fatal(err)
	}
	renderPDFBytes(t, d)
	for _, want := range []string{
		"CloudTrail Audit", "Findings (1)", "CRITICAL", "cloudtrail-tamper", "Top principals",
		"Events by hour (UTC)", "org-cloudtrail-logs",
	} {
		if !drawnContains(d, want) {
			t.Errorf("CloudTrail PDF missing %q", want)
		}
	}
	if drawnContains(d, "more findings not shown") {
		t.Error("dropped-findings note shown with none dropped")
	}

	var buf bytes.Buffer
	if err := PDF(&buf, sampleResult(), sampleMeta(), 10); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Error("PDF output is not a PDF")
	}
}

func TestCloudTrailPDFDropped(t *testing.T) {
	res := sampleResult()
	res.DroppedFindings = 3
	d, err := renderPDF(res, sampleMeta(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if !drawnContains(d, "3 more findings not shown") {
		t.Error("missing dropped-findings note")
	}
}

func TestCloudTrailPDFEmpty(t *testing.T) {
	d, err := renderPDF(engine.Result{}, Meta{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	renderPDFBytes(t, d)
	for _, want := range []string{"Findings (0)", "No matching records"} {
		if !drawnContains(d, want) {
			t.Errorf("empty CloudTrail PDF missing %q", want)
		}
	}
}
