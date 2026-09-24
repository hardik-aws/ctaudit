// Package elblog parses Elastic Load Balancing access logs (Application,
// Network, and Classic load balancers) into one common Entry type.
package elblog

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"
)

// Kind identifies which load balancer type wrote a log.
type Kind string

// Load balancer kinds.
const (
	ALB     Kind = "alb"
	NLB     Kind = "nlb"
	Classic Kind = "classic"
)

// ParseKind accepts "alb", "nlb", "classic" (or "elb"), case-insensitively.
func ParseKind(s string) (Kind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "alb", "app", "application":
		return ALB, nil
	case "nlb", "net", "network":
		return NLB, nil
	case "classic", "elb", "clb":
		return Classic, nil
	}
	return "", fmt.Errorf("unknown load balancer type %q: want alb, nlb, or classic", s)
}

// Entry is one request (ALB, Classic) or TLS connection (NLB). Fields that a
// load balancer type does not log are left empty. A value of "-" in the log
// is stored as "".
type Entry struct {
	Kind Kind
	// Type is the listener protocol as logged: http, https, h2, grpcs, ws,
	// wss, or tls. Classic logs have no type field; it is derived from the
	// request URL scheme instead.
	Type string
	Time time.Time
	LB   string

	ClientIP   string
	ClientPort string
	// Target is the backend "ip:port", or "" when no target was chosen.
	Target string

	// RequestTime, TargetTime, and ResponseTime are in seconds. -1 means the
	// load balancer could not measure the phase (e.g. no target responded).
	RequestTime  float64
	TargetTime   float64
	ResponseTime float64
	// Latency is the total time in seconds: the sum of the three phases for
	// ALB and Classic, or the connection time for NLB. -1 when unknown.
	Latency float64

	ELBStatus    string
	TargetStatus string

	ReceivedBytes int64
	SentBytes     int64

	Method   string
	URL      string
	Protocol string
	// Host and Path are extracted from URL: Host without the port, Path
	// without the query string.
	Host string
	Path string

	UserAgent   string
	SSLCipher   string
	SSLProtocol string

	TargetGroupARN       string
	TraceID              string
	DomainName           string
	CertARN              string
	MatchedRulePriority  string
	RequestCreationTime  time.Time
	Actions              string
	RedirectURL          string
	ErrorReason          string
	TargetList           string
	TargetStatusList     string
	Classification       string
	ClassificationReason string
	ConnTraceID          string

	// Conn marks an ALB connection log record rather than a request. A
	// connection record carries the client, listener, and TLS handshake
	// fields only; the request fields stay empty.
	Conn bool
	// TLSVerifyStatus and the ClientCert fields come from ALB connection
	// logs. The client certificate fields are set only with mutual TLS.
	TLSVerifyStatus    string
	ClientCertSubject  string
	ClientCertValidity string
	ClientCertSerial   string

	// Listener is the listener port for NLB and ALB connection records.
	Listener         string
	TLSHandshakeTime float64 // seconds, -1 when not logged
	IncomingTLSAlert string
	TLSKeyExchange   string
	ALPNFrontend     string
	ALPNBackend      string
}

// HostOrSNI returns the request host, falling back to the TLS SNI domain.
func (e Entry) HostOrSNI() string {
	if e.Host != "" {
		return e.Host
	}
	return e.DomainName
}

// HandshakeFailed reports a connection record on port 443 with no
// negotiated TLS protocol, which means the client connected but the TLS
// handshake never completed. It assumes 443 is an HTTPS listener, since
// connection logs do not record the listener protocol.
func (e Entry) HandshakeFailed() bool {
	return e.Conn && e.Listener == "443" && e.SSLProtocol == ""
}

// ---- tokenizer ----

// fields splits a log line on spaces, treating "..." as one field. A
// backslash inside quotes escapes the next character.
func fields(line string) []string {
	out := make([]string, 0, 40)
	i, n := 0, len(line)
	for i < n {
		for i < n && line[i] == ' ' {
			i++
		}
		if i >= n {
			break
		}
		if line[i] == '"' {
			i++
			var b strings.Builder
			for i < n && line[i] != '"' {
				if line[i] == '\\' && i+1 < n {
					i++
				}
				b.WriteByte(line[i])
				i++
			}
			i++ // closing quote
			out = append(out, b.String())
			continue
		}
		start := i
		for i < n && line[i] != ' ' {
			i++
		}
		out = append(out, line[start:i])
	}
	return out
}

// ---- field helpers ----

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func seconds(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return -1
	}
	return f
}

func millis(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return -1
	}
	return f / 1000
}

func bytesField(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	// NLB logs omit the zone designator; they are UTC.
	t, err := time.Parse("2006-01-02T15:04:05.999999999", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad time %q", s)
	}
	return t, nil
}

// splitHostPort splits "ip:port", "[v6]:port", or "-".
func splitHostPort(s string) (string, string) {
	if s == "-" || s == "" {
		return "", ""
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, ""
	}
	host := strings.TrimSuffix(strings.TrimPrefix(s[:i], "["), "]")
	return host, s[i+1:]
}

// setRequest fills Method, URL, Protocol, Host, and Path from the quoted
// request field "METHOD URL PROTOCOL". Malformed requests, which the load
// balancer logs as "- url -", are kept as far as they go.
func (e *Entry) setRequest(req string) {
	parts := strings.SplitN(req, " ", 3)
	if len(parts) > 0 {
		e.Method = dash(parts[0])
	}
	if len(parts) > 1 {
		e.URL = dash(parts[1])
	}
	if len(parts) > 2 {
		e.Protocol = dash(strings.TrimSpace(parts[2]))
	}
	e.Host, e.Path = splitURL(e.URL)
}

// splitURL extracts the host (without port) and path (without query) from a
// logged absolute URL. It is deliberately lenient rather than using net/url,
// because malformed requests must not lose the host.
func splitURL(u string) (host, p string) {
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	} else if strings.HasPrefix(rest, "/") {
		return "", trimQuery(rest)
	}
	hostport := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		hostport, p = rest[:i], trimQuery(rest[i:])
	}
	host = hostport
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i >= 0 {
			host = host[1:i]
		}
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return strings.ToLower(host), p
}

func trimQuery(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return p[:i]
	}
	return p
}

func sumLatency(a, b, c float64) float64 {
	if a < 0 || b < 0 || c < 0 {
		return -1
	}
	return a + b + c
}

func schemeOf(u string) string {
	if i := strings.Index(u, "://"); i > 0 {
		return strings.ToLower(u[:i])
	}
	return ""
}

// ---- parsers ----

// minimum field counts; anything shorter is not a log line of that kind.
const (
	albMinFields     = 13
	nlbMinFields     = 11
	classicMinFields = 12
)

// ParseALB parses one Application Load Balancer log line. Fields past the
// documented set are ignored, so newer log versions still parse.
func ParseALB(line string) (Entry, error) {
	f := fields(line)
	if len(f) < albMinFields {
		return Entry{}, fmt.Errorf("alb: %d fields, want at least %d", len(f), albMinFields)
	}
	at := func(i int) string {
		if i < len(f) {
			return dash(f[i])
		}
		return ""
	}
	t, err := parseTime(f[1])
	if err != nil {
		return Entry{}, fmt.Errorf("alb: %w", err)
	}
	e := Entry{Kind: ALB, Type: f[0], Time: t, LB: f[2], TLSHandshakeTime: -1}
	e.ClientIP, e.ClientPort = splitHostPort(f[3])
	e.Target = at(4)
	e.RequestTime, e.TargetTime, e.ResponseTime = seconds(f[5]), seconds(f[6]), seconds(f[7])
	e.Latency = sumLatency(e.RequestTime, e.TargetTime, e.ResponseTime)
	e.ELBStatus, e.TargetStatus = at(8), at(9)
	e.ReceivedBytes, e.SentBytes = bytesField(f[10]), bytesField(f[11])
	e.setRequest(f[12])
	e.UserAgent = at(13)
	e.SSLCipher, e.SSLProtocol = at(14), at(15)
	e.TargetGroupARN = at(16)
	e.TraceID = at(17)
	e.DomainName = strings.ToLower(at(18))
	e.CertARN = at(19)
	e.MatchedRulePriority = at(20)
	if s := at(21); s != "" {
		e.RequestCreationTime, _ = parseTime(s)
	}
	e.Actions, e.RedirectURL, e.ErrorReason = at(22), at(23), at(24)
	e.TargetList, e.TargetStatusList = at(25), at(26)
	e.Classification, e.ClassificationReason = at(27), at(28)
	e.ConnTraceID = at(29)
	return e, nil
}

// albConnMinFields is the connection log field count up to and including
// the load balancer id.
const albConnMinFields = 14

// ParseALBConn parses one Application Load Balancer connection log line.
// The returned Entry has Conn set. Fields past the documented set are
// ignored, so newer log versions still parse.
func ParseALBConn(line string) (Entry, error) {
	f := fields(line)
	if len(f) < albConnMinFields {
		return Entry{}, fmt.Errorf("alb conn: %d fields, want at least %d", len(f), albConnMinFields)
	}
	t, err := parseTime(f[0])
	if err != nil {
		return Entry{}, fmt.Errorf("alb conn: %w", err)
	}
	e := Entry{
		Kind:               ALB,
		Conn:               true,
		Time:               t,
		ClientIP:           dash(f[1]),
		ClientPort:         dash(f[2]),
		Listener:           dash(f[3]),
		SSLProtocol:        dash(f[4]),
		SSLCipher:          dash(f[5]),
		TLSHandshakeTime:   seconds(f[6]),
		ClientCertSubject:  dash(f[7]),
		ClientCertValidity: dash(f[8]),
		ClientCertSerial:   dash(f[9]),
		TLSVerifyStatus:    dash(f[10]),
		ConnTraceID:        dash(f[11]),
		TLSKeyExchange:     dash(f[12]),
		LB:                 dash(f[13]),
		RequestTime:        -1,
		TargetTime:         -1,
		ResponseTime:       -1,
		Latency:            -1,
	}
	return e, nil
}

// ParseNLB parses one Network Load Balancer (TLS listener) log line.
func ParseNLB(line string) (Entry, error) {
	f := fields(line)
	if len(f) < nlbMinFields {
		return Entry{}, fmt.Errorf("nlb: %d fields, want at least %d", len(f), nlbMinFields)
	}
	at := func(i int) string {
		if i < len(f) {
			return dash(f[i])
		}
		return ""
	}
	t, err := parseTime(f[2])
	if err != nil {
		return Entry{}, fmt.Errorf("nlb: %w", err)
	}
	e := Entry{Kind: NLB, Type: f[0], Time: t, LB: f[3], Listener: at(4),
		RequestTime: -1, TargetTime: -1, ResponseTime: -1}
	e.ClientIP, e.ClientPort = splitHostPort(f[5])
	e.Target = at(6)
	e.Latency = millis(f[7])
	e.TLSHandshakeTime = millis(f[8])
	e.ReceivedBytes, e.SentBytes = bytesField(f[9]), bytesField(f[10])
	e.IncomingTLSAlert = at(11)
	e.CertARN = at(12)
	e.SSLCipher, e.SSLProtocol = at(14), at(15)
	e.TLSKeyExchange = at(16)
	e.DomainName = strings.ToLower(at(17))
	e.ALPNFrontend, e.ALPNBackend = at(18), at(19)
	if s := at(21); s != "" {
		e.RequestCreationTime, _ = parseTime(s)
	}
	return e, nil
}

// ParseClassic parses one Classic Load Balancer log line.
func ParseClassic(line string) (Entry, error) {
	f := fields(line)
	if len(f) < classicMinFields {
		return Entry{}, fmt.Errorf("classic: %d fields, want at least %d", len(f), classicMinFields)
	}
	at := func(i int) string {
		if i < len(f) {
			return dash(f[i])
		}
		return ""
	}
	t, err := parseTime(f[0])
	if err != nil {
		return Entry{}, fmt.Errorf("classic: %w", err)
	}
	e := Entry{Kind: Classic, Time: t, LB: f[1], TLSHandshakeTime: -1}
	e.ClientIP, e.ClientPort = splitHostPort(f[2])
	e.Target = at(3)
	e.RequestTime, e.TargetTime, e.ResponseTime = seconds(f[4]), seconds(f[5]), seconds(f[6])
	e.Latency = sumLatency(e.RequestTime, e.TargetTime, e.ResponseTime)
	e.ELBStatus, e.TargetStatus = at(7), at(8)
	e.ReceivedBytes, e.SentBytes = bytesField(f[9]), bytesField(f[10])
	e.setRequest(f[11])
	e.UserAgent = at(12)
	e.SSLCipher, e.SSLProtocol = at(13), at(14)
	e.Type = schemeOf(e.URL)
	if e.Type == "" {
		e.Type = "tcp"
	}
	return e, nil
}

// ---- keys ----

const keyMarker = "_elasticloadbalancing_"

// keyLBSegment returns the load balancer segment of a log object's file
// name: "app.<name>.<id>", "net.<name>.<id>", or a Classic "<name>".
func keyLBSegment(key string) string {
	base := path.Base(key)
	i := strings.Index(base, keyMarker)
	if i < 0 {
		return ""
	}
	rest := base[i+len(keyMarker):]
	j := strings.IndexByte(rest, '_') // skip the region
	if j < 0 {
		return ""
	}
	rest = rest[j+1:]
	if k := strings.IndexByte(rest, '_'); k >= 0 {
		return rest[:k]
	}
	return ""
}

// KindFromKey detects the load balancer kind from a log object key. It
// returns "" for keys that are not ELB access logs.
func KindFromKey(key string) Kind {
	seg := keyLBSegment(key)
	switch {
	case seg == "":
		return ""
	case strings.HasPrefix(seg, "app."):
		return ALB
	case strings.HasPrefix(seg, "net."):
		return NLB
	}
	return Classic
}

// LBNameFromKey returns the load balancer name encoded in a log object key,
// e.g. "k8s-web-0123456789".
func LBNameFromKey(key string) string {
	seg := keyLBSegment(key)
	if strings.HasPrefix(seg, "app.") || strings.HasPrefix(seg, "net.") {
		parts := strings.Split(seg, ".")
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return seg
}

// IsConnLogKey reports whether key is an ALB connection log object. These
// share the access log prefix but start with "conn_log_" and use their own
// line format.
func IsConnLogKey(key string) bool {
	return strings.HasPrefix(path.Base(key), "conn_log_")
}

// IsLogKey reports whether a listed key is an ELB access or connection log
// object, as
// opposed to the ELBAccessLogTestFile or stray content.
func IsLogKey(key string) bool {
	if !strings.HasSuffix(key, ".log.gz") && !strings.HasSuffix(key, ".log") {
		return false
	}
	return KindFromKey(key) != ""
}

// ---- decoding ----

// maxLine bounds one log line. ALB lines with long URLs and user agents stay
// well below this.
const maxLine = 1 << 20

// LineError reports lines of an object that could not be parsed. Decode
// returns it alongside every entry that did parse.
type LineError struct {
	Bad   int
	First error
}

func (e *LineError) Error() string {
	return fmt.Sprintf("%d unparseable lines, first: %v", e.Bad, e.First)
}

// Decode reads one log object, gzipped or plain, and parses every line with
// the parser for the kind encoded in key. Unparseable lines are skipped and
// reported through a *LineError; I/O and gzip errors return no entries.
func Decode(key string, r io.Reader) ([]Entry, error) {
	var parse func(string) (Entry, error)
	switch KindFromKey(key) {
	case ALB:
		parse = ParseALB
		if IsConnLogKey(key) {
			parse = ParseALBConn
		}
	case NLB:
		parse = ParseNLB
	case Classic:
		parse = ParseClassic
	default:
		return nil, errors.New("not an ELB access log key")
	}

	br := bufio.NewReader(r)
	var src io.Reader = br
	// Sniff the gzip magic rather than trusting the suffix: Classic logs
	// are plain text, ALB and NLB logs are gzipped.
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		src = zr
	}

	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	var out []Entry
	var lineErr *LineError
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		e, err := parse(line)
		if err != nil {
			if lineErr == nil {
				lineErr = &LineError{First: err}
			}
			lineErr.Bad++
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if lineErr != nil {
		return out, lineErr
	}
	return out, nil
}
