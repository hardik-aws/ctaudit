package report

import (
	_ "embed"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/signintech/gopdf"

	"github.com/gsmappdev/ctaudit/internal/stats"
)

// The Go fonts (BSD licence, see fonts/LICENSE) are embedded so the PDF
// renders the same everywhere without system fonts.
var (
	//go:embed fonts/Go-Regular.ttf
	fontRegular []byte
	//go:embed fonts/Go-Bold.ttf
	fontBold []byte
)

const (
	fontFamily     = "go"
	fontFamilyBold = "go-bold"

	pdfMargin   = 40.0
	pdfRowH     = 14.0
	pdfBodySize = 9.0
	pdfFooterH  = 24.0
	pdfKeyWidth = 150.0
	pdfChartH   = 80.0
	// pdfHeadingRoom is how much space must remain below a heading;
	// otherwise the heading moves to a new page so it is never orphaned.
	pdfHeadingRoom = 80.0
)

var (
	pdfPageW    = gopdf.PageSizeA4.W
	pdfPageH    = gopdf.PageSizeA4.H
	pdfContentW = pdfPageW - 2*pdfMargin

	colText   = [3]uint8{0x1f, 0x29, 0x37}
	colMuted  = [3]uint8{0x6b, 0x72, 0x80}
	colAccent = [3]uint8{0x1d, 0x4e, 0xd8}
	colRule   = [3]uint8{0xd1, 0xd5, 0xdb}
	colHead   = [3]uint8{0xe5, 0xe7, 0xeb}
	colZebra  = [3]uint8{0xf3, 0xf4, 0xf6}
	colBar    = [3]uint8{0x93, 0xc5, 0xfd}
)

// pdfMaxErrors caps the error list; the rest are summarised in one line.
const pdfMaxErrors = 20

// pdfNoCompress turns off stream compression so tests can count page objects.
var pdfNoCompress bool

// pdfColumn is one table column. Width is a fraction of the content width.
type pdfColumn struct {
	Header string
	Width  float64
	Right  bool
}

// pdfTable is a titled table; every cell is plain text.
type pdfTable struct {
	Title   string
	Columns []pdfColumn
	Rows    [][]string
}

// pdfDoc is a small flowing-layout helper over gopdf: callers add blocks top
// to bottom and it breaks pages as needed. The first drawing error is kept
// and returned by writeTo, so block methods need no error handling.
type pdfDoc struct {
	pdf    *gopdf.GoPdf
	footer string
	// drawn logs every string drawn, in order. gopdf stores text as glyph
	// IDs, so tests assert on this log instead of the PDF bytes.
	drawn []string
	err   error
}

// newPDFDoc starts an A4 portrait document with the embedded fonts and one
// empty page. footer is followed by " · page N of M" on every page.
func newPDFDoc(footer string) (*pdfDoc, error) {
	pdf := &gopdf.GoPdf{}
	pdf.Start(gopdf.Config{PageSize: *gopdf.PageSizeA4})
	if pdfNoCompress {
		pdf.SetNoCompression()
	}
	if err := pdf.AddTTFFontData(fontFamily, fontRegular); err != nil {
		return nil, fmt.Errorf("pdf font: %w", err)
	}
	if err := pdf.AddTTFFontData(fontFamilyBold, fontBold); err != nil {
		return nil, fmt.Errorf("pdf font: %w", err)
	}
	d := &pdfDoc{pdf: pdf, footer: footer}
	d.newPage()
	return d, d.err
}

func (d *pdfDoc) keep(err error) {
	if err != nil && d.err == nil {
		d.err = err
	}
}

func (d *pdfDoc) newPage() {
	d.pdf.AddPage()
	d.pdf.SetXY(pdfMargin, pdfMargin)
}

// need starts a new page unless h points remain above the footer. It
// reports whether a page was added.
func (d *pdfDoc) need(h float64) bool {
	if d.pdf.GetY()+h <= pdfPageH-pdfMargin-pdfFooterH {
		return false
	}
	d.newPage()
	return true
}

func (d *pdfDoc) font(bold bool, size float64, c [3]uint8) {
	family := fontFamily
	if bold {
		family = fontFamilyBold
	}
	d.keep(d.pdf.SetFont(family, "", size))
	d.pdf.SetTextColor(c[0], c[1], c[2])
}

// text draws s, fitted to w, in a box at (x, y) of height h. The font must
// already be set.
func (d *pdfDoc) text(x, y, w, h float64, s string, right bool) {
	s = d.fit(s, w)
	d.drawn = append(d.drawn, s)
	d.pdf.SetXY(x, y)
	align := gopdf.Left | gopdf.Middle
	if right {
		align = gopdf.Right | gopdf.Middle
	}
	d.keep(d.pdf.CellWithOption(&gopdf.Rect{W: w, H: h}, s, gopdf.CellOption{Align: align}))
}

func (d *pdfDoc) fill(x, y, w, h float64, c [3]uint8) {
	d.pdf.SetFillColor(c[0], c[1], c[2])
	d.pdf.RectFromUpperLeftWithStyle(x, y, w, h, "F")
}

func (d *pdfDoc) rule(y float64, c [3]uint8) {
	d.pdf.SetStrokeColor(c[0], c[1], c[2])
	d.pdf.SetLineWidth(0.5)
	d.pdf.Line(pdfMargin, y, pdfMargin+pdfContentW, y)
}

// fit sanitises s with clean and, if it is wider than width in the current
// font, truncates it on a rune boundary and appends "…".
func (d *pdfDoc) fit(s string, width float64) string {
	s = clean(s)
	if !utf8.ValidString(s) {
		s = string([]rune(s))
	}
	if d.width(s) <= width {
		return s
	}
	runes := []rune(s)
	lo, hi := 0, len(runes)
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if d.width(string(runes[:mid])+"…") <= width {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	if lo == 0 {
		return ""
	}
	return string(runes[:lo]) + "…"
}

func (d *pdfDoc) width(s string) float64 {
	w, err := d.pdf.MeasureTextWidth(s)
	if err != nil {
		d.keep(err)
		return 0
	}
	return w
}

// title draws the report title and a muted subtitle line.
func (d *pdfDoc) title(text, subtitle string) {
	d.pdf.SetInfo(gopdf.PdfInfo{Title: clean(text), Creator: "ctaudit", Producer: "ctaudit"})
	y := d.pdf.GetY()
	d.font(true, 18, colText)
	d.text(pdfMargin, y, pdfContentW, 24, text, false)
	if subtitle != "" {
		d.font(false, 10, colMuted)
		d.text(pdfMargin, y+24, pdfContentW, 14, subtitle, false)
		y += 14
	}
	d.pdf.SetXY(pdfMargin, y+30)
}

// heading draws a section heading with a rule under it.
func (d *pdfDoc) heading(text string) {
	d.need(pdfHeadingRoom)
	y := d.pdf.GetY() + 8
	d.font(true, 12, colAccent)
	d.text(pdfMargin, y, pdfContentW, 18, text, false)
	d.rule(y+19, colRule)
	d.pdf.SetXY(pdfMargin, y+24)
}

// kv draws label/value pairs, one per line.
func (d *pdfDoc) kv(pairs [][2]string) {
	for _, p := range pairs {
		d.need(pdfRowH)
		y := d.pdf.GetY()
		d.font(false, pdfBodySize, colMuted)
		d.text(pdfMargin, y, pdfKeyWidth, pdfRowH, p[0], false)
		d.font(false, pdfBodySize, colText)
		d.text(pdfMargin+pdfKeyWidth, y, pdfContentW-pdfKeyWidth, pdfRowH, p[1], false)
		d.pdf.SetXY(pdfMargin, y+pdfRowH)
	}
	d.gap()
}

// table draws t with zebra rows. The header row repeats after a page break.
func (d *pdfDoc) table(t pdfTable) {
	if t.Title != "" {
		d.heading(t.Title)
	}
	d.need(2 * pdfRowH)
	d.tableHeader(t.Columns)
	for i, row := range t.Rows {
		if d.need(pdfRowH) {
			d.tableHeader(t.Columns)
		}
		y := d.pdf.GetY()
		if i%2 == 1 {
			d.fill(pdfMargin, y, pdfContentW, pdfRowH, colZebra)
		}
		d.font(false, pdfBodySize, colText)
		d.cells(t.Columns, y, func(j int) string {
			if j < len(row) {
				return row[j]
			}
			return ""
		})
		d.pdf.SetXY(pdfMargin, y+pdfRowH)
	}
	d.gap()
}

func (d *pdfDoc) tableHeader(cols []pdfColumn) {
	y := d.pdf.GetY()
	d.fill(pdfMargin, y, pdfContentW, pdfRowH, colHead)
	d.font(true, pdfBodySize, colText)
	d.cells(cols, y, func(j int) string { return cols[j].Header })
	d.pdf.SetXY(pdfMargin, y+pdfRowH)
}

// cells draws one row of cells with 4 pt of padding on each side.
func (d *pdfDoc) cells(cols []pdfColumn, y float64, value func(int) string) {
	const pad = 4.0
	x := pdfMargin
	for j, c := range cols {
		w := c.Width * pdfContentW
		d.text(x+pad, y, w-2*pad, pdfRowH, value(j), c.Right)
		x += w
	}
}

// hours draws a 24-bar chart under a heading. bars come from hourBars. The
// peak hour is drawn in the accent colour.
func (d *pdfDoc) hours(bars []bar, label string) {
	d.heading(label)
	d.need(pdfChartH + 2*pdfRowH)
	top := d.pdf.GetY() + 10 // room for the count above the tallest bar
	base := top + pdfChartH
	slot := pdfContentW / float64(max(len(bars), 1))
	peak := -1
	for i, b := range bars {
		if b.Count > 0 && (peak < 0 || b.Count > bars[peak].Count) {
			peak = i
		}
	}
	for i, b := range bars {
		x := pdfMargin + float64(i)*slot
		h := pdfChartH * float64(b.Pct) / 100
		if h > 0 {
			c := colBar
			if i == peak {
				c = colAccent
			}
			d.fill(x+2, base-h, slot-4, h, c)
		}
		d.font(false, 6, colMuted)
		if b.Count > 0 {
			d.text(x, base-h-9, slot, 9, strconv.Itoa(b.Count), false)
		}
		d.text(x, base+1, slot, 10, b.Key, false)
	}
	d.rule(base, colRule)
	d.pdf.SetXY(pdfMargin, base+14)
	d.gap()
}

// note draws a single muted line.
func (d *pdfDoc) note(text string) {
	d.need(pdfRowH)
	y := d.pdf.GetY()
	d.font(false, pdfBodySize, colMuted)
	d.text(pdfMargin, y, pdfContentW, pdfRowH, text, false)
	d.pdf.SetXY(pdfMargin, y+pdfRowH)
}

// errorList draws an "Errors (N)" section with the first pdfMaxErrors
// entries. It draws nothing when errs is empty.
func (d *pdfDoc) errorList(errs []string) {
	if len(errs) == 0 {
		return
	}
	d.heading(fmt.Sprintf("Errors (%d)", len(errs)))
	for i, e := range errs {
		if i == pdfMaxErrors {
			d.note(fmt.Sprintf("and %d more", len(errs)-i))
			break
		}
		d.note(e)
	}
	d.gap()
}

func (d *pdfDoc) gap() { d.pdf.SetXY(pdfMargin, d.pdf.GetY()+8) }

// writeTo draws the footer on every page and writes the document.
func (d *pdfDoc) writeTo(w io.Writer) error {
	if d.err != nil {
		return d.err
	}
	n := d.pdf.GetNumberOfPages()
	for i := 1; i <= n; i++ {
		if err := d.pdf.SetPage(i); err != nil {
			return err
		}
		d.font(false, 7, colMuted)
		d.text(pdfMargin, pdfPageH-pdfMargin, pdfContentW, 10,
			fmt.Sprintf("%s · page %d of %d", d.footer, i, n), false)
	}
	if d.err != nil {
		return d.err
	}
	_, err := d.pdf.WriteTo(w)
	return err
}

// newReportPDF starts a report: the title, the UTC window, and the scan
// scope. The footer carries the generation time.
func newReportPDF(title string, meta Meta) (*pdfDoc, error) {
	generated := formatTime(meta.GeneratedAt)
	d, err := newPDFDoc("ctaudit · generated " + generated)
	if err != nil {
		return nil, err
	}
	d.title(title, fmt.Sprintf("%s .. %s UTC (%d days)",
		meta.Since.Format(dayLayout), meta.Until.Format(dayLayout), meta.Days()))
	d.kv([][2]string{
		{"Bucket", dashIfEmpty(meta.Bucket)},
		{"Accounts", dashIfEmpty(strings.Join(meta.Accounts, ", "))},
		{"Regions", dashIfEmpty(strings.Join(meta.Regions, ", "))},
		{"Generated", generated},
	})
	return d, nil
}

// rankedPDFTable turns a top-N list into a key/count/percent table. total is
// the count the percentages are relative to; 0 leaves the column blank.
func rankedPDFTable(title, keyHeader, countHeader string, pairs []stats.Pair, total int) pdfTable {
	t := pdfTable{
		Title: title,
		Columns: []pdfColumn{
			{Header: keyHeader, Width: 0.70},
			{Header: countHeader, Width: 0.18, Right: true},
			{Header: "%", Width: 0.12, Right: true},
		},
	}
	for _, p := range pairs {
		pct := ""
		if total > 0 {
			pct = fmt.Sprintf("%.1f", float64(p.Count)*100/float64(total))
		}
		t.Rows = append(t.Rows, []string{p.Key, groupDigits(p.Count), pct})
	}
	return t
}

// pdfTones maps the chart tones to print colours.
var pdfTones = map[string][3]uint8{
	"ok":     {0x2f, 0x8a, 0x57},
	"info":   {0x3b, 0x62, 0xb0},
	"warn":   {0xa8, 0x69, 0x0f},
	"crit":   {0xc0, 0x39, 0x2b},
	"accent": colAccent,
	"muted":  {0x9c, 0xa3, 0xaf},
}

func pdfTone(t string) [3]uint8 {
	if c, ok := pdfTones[t]; ok {
		return c
	}
	return colMuted
}

// chart draws a time chart under a heading, followed by its legend table.
// It mirrors chartSVG: stacked bars and lines on the left axis, lines on
// the right axis, and dashed guide lines.
func (d *pdfDoc) chart(c seriesChart) {
	n := c.Len()
	if n == 0 {
		return
	}
	const axisW, labelH = 40.0, 10.0
	// Keep the heading, the plot, and the first legend rows together.
	d.need(pdfChartH + labelH + 6*pdfRowH + 30)
	d.heading(c.Title)
	hasRight := false
	for _, l := range c.Lines {
		hasRight = hasRight || l.Right
	}
	left := pdfMargin + axisW
	plotW := pdfContentW - axisW
	if hasRight {
		plotW -= axisW
	}
	top := d.pdf.GetY() + 4
	base := top + pdfChartH
	slot := plotW / float64(n)

	leftMax, rightMax := 0.0, 0.0
	for i := 0; i < n; i++ {
		stack := 0.0
		for _, b := range c.Bars {
			stack += b.Values[i]
		}
		leftMax = max(leftMax, stack)
	}
	for _, l := range c.Lines {
		for _, v := range l.Values {
			if v != v { // NaN
				continue
			}
			if l.Right {
				rightMax = max(rightMax, v)
			} else {
				leftMax = max(leftMax, v)
			}
		}
	}
	for _, g := range c.Guides {
		leftMax = max(leftMax, g.Value)
	}
	leftMax, rightMax = niceMax(leftMax), niceMax(rightMax)
	yl := func(v float64) float64 { return base - v/leftMax*pdfChartH }
	yr := func(v float64) float64 { return base - v/rightMax*pdfChartH }

	d.pdf.SetLineType("solid")
	for i := 0; i <= 4; i++ {
		f := float64(i) / 4
		y := base - f*pdfChartH
		d.pdf.SetStrokeColor(colRule[0], colRule[1], colRule[2])
		d.pdf.SetLineWidth(0.3)
		d.pdf.Line(left, y, left+plotW, y)
		d.font(false, 6, colMuted)
		d.text(pdfMargin, y-labelH/2, axisW-4, labelH, axisLabel(f*leftMax, c.LeftSeconds), true)
		if hasRight {
			d.text(left+plotW+4, y-labelH/2, axisW-4, labelH, axisLabel(f*rightMax, c.RightSeconds), false)
		}
	}
	ticks := min(6, n)
	multiDay := c.Step*time.Duration(n) > 24*time.Hour || c.Start.YearDay() != c.Start.Add(c.Step*time.Duration(n)-1).YearDay()
	for i := 0; i < ticks; i++ {
		idx := i * n / ticks
		x := left + float64(idx)*slot
		d.text(x, base+1, 60, labelH, timeLabel(c.Start.Add(c.Step*time.Duration(idx)), c.Step, multiDay), false)
	}

	bw := max(slot*0.8, 0.4)
	for i := 0; i < n; i++ {
		stack := 0.0
		for _, s := range c.Bars {
			v := s.Values[i]
			if v <= 0 {
				continue
			}
			y0, y1 := yl(stack), yl(stack+v)
			d.fill(left+float64(i)*slot+(slot-bw)/2, y1, bw, max(y0-y1, 0.3), pdfTone(s.Tone))
			stack += v
		}
	}
	for _, g := range c.Guides {
		col := pdfTone(g.Tone)
		d.pdf.SetStrokeColor(col[0], col[1], col[2])
		d.pdf.SetLineWidth(0.5)
		d.pdf.SetLineType("dashed")
		d.pdf.Line(left, yl(g.Value), left+plotW, yl(g.Value))
		d.pdf.SetLineType("solid")
	}
	for _, l := range c.Lines {
		y := yl
		if l.Right {
			y = yr
		}
		col := pdfTone(l.Tone)
		d.pdf.SetStrokeColor(col[0], col[1], col[2])
		d.pdf.SetLineWidth(0.9)
		prev := -1
		for i, v := range l.Values {
			if v != v {
				prev = -1
				continue
			}
			x := left + (float64(i)+0.5)*slot
			if prev >= 0 {
				px := left + (float64(prev)+0.5)*slot
				d.pdf.Line(px, y(l.Values[prev]), x, y(v))
			} else if i+1 >= len(l.Values) || l.Values[i+1] != l.Values[i+1] {
				d.fill(x-0.8, y(v)-0.8, 1.6, 1.6, col)
			}
			prev = i
		}
	}
	d.rule(base, colRule)
	d.pdf.SetXY(pdfMargin, base+labelH+4)

	t := pdfTable{Columns: []pdfColumn{
		{Header: "Series", Width: 0.44},
		{Header: "Min", Width: 0.14, Right: true},
		{Header: "Max", Width: 0.14, Right: true},
		{Header: "Avg", Width: 0.14, Right: true},
		{Header: "Last", Width: 0.14, Right: true},
	}}
	for _, r := range c.Legend() {
		t.Rows = append(t.Rows, []string{r.Name, r.Min, r.Max, r.Avg, r.Last})
	}
	d.table(t)
}
