// Package s3log decodes Amazon S3 server access logs: plain-text objects,
// one space-delimited request per line. The query string of the request URI
// and the referer (presigned URLs carry X-Amz-Credential, X-Amz-Signature,
// and session tokens there), the host ID, the bucket owner, and the version
// ID are dropped here so they can never reach a report or a sink.
package s3log

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Anonymous is the principal reported for unauthenticated requests, which
// S3 logs with a requester of "-".
const Anonymous = "anonymous"

// Entry is one S3 server access log record.
type Entry struct {
	Time      time.Time
	Bucket    string
	RemoteIP  string
	Requester string // "" for an anonymous request
	RequestID string
	Operation string
	Key       string // as logged, URL-encoded

	Method string
	Path   string // request URI path without its query string
	Proto  string

	Status    int // 0 when not logged
	ErrorCode string

	BytesSent    int64
	ObjectSize   int64
	TotalTimeMS  int64 // -1 when not logged
	TurnaroundMS int64 // -1 when not logged

	Referer        string // without its query string or fragment
	UserAgent      string
	SigVersion     string
	CipherSuite    string
	AuthType       string
	HostHeader     string
	TLSVersion     string // normalised to "TLSv1.2" form
	AccessPointARN string
	ACLRequired    bool
	// PlainHTTP is true when the record has a tls_version field, it is "-",
	// and the operation is a REST request: the request used plain HTTP.
	PlainHTTP bool
}

const timeLayout = "02/Jan/2006:15:04:05 -0700"

// Field positions after splitting; the bracketed time is one field.
// version_id (17) and host_id (18) are never read.
const (
	fBucket      = 1
	fTime        = 2
	fRemoteIP    = 3
	fRequester   = 4
	fRequestID   = 5
	fOperation   = 6
	fKey         = 7
	fRequestURI  = 8
	fStatus      = 9
	fErrorCode   = 10
	fBytesSent   = 11
	fObjectSize  = 12
	fTotalTime   = 13
	fTurnaround  = 14
	fReferer     = 15
	fUserAgent   = 16
	fSigVersion  = 19
	fCipherSuite = 20
	fAuthType    = 21
	fHostHeader  = 22
	fTLSVersion  = 23
	fAccessPoint = 24
	fACLRequired = 25

	// minFields is the shortest record accepted: through http_status.
	minFields = fStatus + 1
)

// Parse decodes one log line. Records older than a field are accepted and
// the missing fields left empty; fields past acl_required are ignored.
func Parse(line string) (Entry, error) {
	f, err := fields(line)
	if err != nil {
		return Entry{}, err
	}
	if len(f) < minFields {
		return Entry{}, fmt.Errorf("want at least %d fields, got %d", minFields, len(f))
	}
	t, err := time.Parse(timeLayout, f[fTime])
	if err != nil {
		return Entry{}, errors.New("bad time field")
	}
	get := func(i int) string {
		if i < len(f) && f[i] != "-" {
			return f[i]
		}
		return ""
	}
	e := Entry{
		Time:           t.UTC(),
		Bucket:         get(fBucket),
		RemoteIP:       get(fRemoteIP),
		Requester:      get(fRequester),
		RequestID:      get(fRequestID),
		Operation:      get(fOperation),
		Key:            get(fKey),
		ErrorCode:      get(fErrorCode),
		Referer:        stripQuery(get(fReferer)),
		UserAgent:      get(fUserAgent),
		SigVersion:     get(fSigVersion),
		CipherSuite:    get(fCipherSuite),
		AuthType:       get(fAuthType),
		HostHeader:     get(fHostHeader),
		TLSVersion:     normTLS(get(fTLSVersion)),
		AccessPointARN: get(fAccessPoint),
		ACLRequired:    strings.EqualFold(get(fACLRequired), "yes"),
	}
	if e.Bucket == "" || e.Operation == "" {
		return Entry{}, errors.New("missing bucket or operation")
	}
	e.Method, e.Path, e.Proto = splitRequest(get(fRequestURI))
	e.Status = int(num(get(fStatus), 0))
	e.BytesSent = num(get(fBytesSent), 0)
	e.ObjectSize = num(get(fObjectSize), 0)
	e.TotalTimeMS = num(get(fTotalTime), -1)
	e.TurnaroundMS = num(get(fTurnaround), -1)
	e.PlainHTTP = len(f) > fTLSVersion && f[fTLSVersion] == "-" && strings.HasPrefix(e.Operation, "REST.")
	return e, nil
}

// fields splits a line on spaces. "[...]" and "\"...\"" are single fields
// without their delimiters; inside quotes a backslash escapes the next byte.
func fields(line string) ([]string, error) {
	var out []string
	for i := 0; i < len(line); {
		switch line[i] {
		case ' ':
			i++
		case '[':
			j := strings.IndexByte(line[i+1:], ']')
			if j < 0 {
				return nil, errors.New("unterminated [")
			}
			out = append(out, line[i+1:i+1+j])
			i += j + 2
		case '"':
			var b strings.Builder
			j := i + 1
			for ; j < len(line) && line[j] != '"'; j++ {
				if line[j] == '\\' && j+1 < len(line) {
					j++
				}
				b.WriteByte(line[j])
			}
			if j >= len(line) {
				return nil, errors.New("unterminated quote")
			}
			out = append(out, b.String())
			i = j + 1
		default:
			j := strings.IndexByte(line[i:], ' ')
			if j < 0 {
				j = len(line) - i
			}
			out = append(out, line[i:i+j])
			i += j
		}
	}
	return out, nil
}

// splitRequest splits "GET /key?query HTTP/1.1" and drops the query.
func splitRequest(s string) (method, path, proto string) {
	if s == "" {
		return "", "", ""
	}
	method, rest, _ := strings.Cut(s, " ")
	if i := strings.LastIndexByte(rest, ' '); i >= 0 && strings.HasPrefix(rest[i+1:], "HTTP/") {
		rest, proto = rest[:i], rest[i+1:]
	}
	return method, stripQuery(rest), proto
}

// stripQuery removes everything from the first "?" or "#".
func stripQuery(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		return s[:i]
	}
	return s
}

// normTLS turns "TLSV1.2" (as in the AWS documentation) into "TLSv1.2".
func normTLS(s string) string {
	if len(s) > 4 && strings.EqualFold(s[:4], "tlsv") {
		return "TLSv" + s[4:]
	}
	return s
}

// num parses an integer field, returning unknown for "" or garbage.
func num(s string, unknown int64) int64 {
	if s == "" {
		return unknown
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return unknown
	}
	return n
}

var (
	writeOps = map[string]bool{
		"REST.PUT.OBJECT": true, "REST.POST.OBJECT": true, "REST.COPY.OBJECT": true,
		"REST.POST.UPLOADS": true, "REST.PUT.PART": true, "REST.COPY.PART": true, "REST.POST.UPLOAD": true,
	}
	deleteOps = map[string]bool{"REST.DELETE.OBJECT": true, "BATCH.DELETE.OBJECT": true}
	readOps   = map[string]bool{
		"REST.GET.OBJECT": true, "REST.HEAD.OBJECT": true, "REST.GET.BUCKET": true,
		"REST.GET.BUCKETVERSIONS": true, "REST.COPY.OBJECT_GET": true,
	}
	accessOps = map[string]bool{
		"REST.PUT.BUCKETPOLICY": true, "REST.DELETE.BUCKETPOLICY": true, "REST.PUT.ACL": true,
		"REST.PUT.PUBLIC_ACCESS_BLOCK": true, "REST.DELETE.PUBLIC_ACCESS_BLOCK": true,
	}
)

// Principal returns the requester, or Anonymous for an unauthenticated
// request.
func (e Entry) Principal() string {
	if e.Requester == "" {
		return Anonymous
	}
	return e.Requester
}

// StatusClass maps 200 to "2xx"; 0, 1xx, and anything odd are "other".
func (e Entry) StatusClass() string {
	if e.Status >= 200 && e.Status < 600 {
		return strconv.Itoa(e.Status/100) + "xx"
	}
	return "other"
}

// Success reports a 2xx status.
func (e Entry) Success() bool { return e.Status >= 200 && e.Status < 300 }

// IsError reports a status of 400 or higher, or a logged error code.
func (e Entry) IsError() bool { return e.Status >= 400 || e.ErrorCode != "" }

// Denied reports a 403 or an AccessDenied error code.
func (e Entry) Denied() bool { return e.Status == 403 || e.ErrorCode == "AccessDenied" }

// IsObjectWrite reports an operation that creates or overwrites object data.
func (e Entry) IsObjectWrite() bool { return writeOps[e.Operation] }

// IsObjectDelete reports an operation that deletes one object. A
// multi-object delete logs one BATCH.DELETE.OBJECT row per key.
func (e Entry) IsObjectDelete() bool { return deleteOps[e.Operation] }

// IsMultiDelete reports the DeleteObjects request itself.
func (e Entry) IsMultiDelete() bool { return e.Operation == "REST.POST.MULTI_OBJECT_DELETE" }

// IsObjectRead reports a REST read or list of object data. Website
// endpoint operations (WEBSITE.*) are not included: that endpoint only ever
// serves anonymous requests by design.
func (e Entry) IsObjectRead() bool { return readOps[e.Operation] }

// IsAccessChange reports a change to a bucket policy, a bucket or object
// ACL, or a public access block.
func (e Entry) IsAccessChange() bool { return accessOps[e.Operation] }

// WeakTLS reports TLS below 1.2.
func (e Entry) WeakTLS() bool {
	switch e.TLSVersion {
	case "TLSv1", "TLSv1.0", "TLSv1.1":
		return true
	}
	return false
}

// SigV2 reports a request signed with Signature Version 2.
func (e Entry) SigV2() bool { return e.SigVersion == "SigV2" }

// logKey matches the YYYY-MM-DD-hh-mm-ss-<unique> tail of every log object.
var logKey = regexp.MustCompile(`\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-[0-9A-Za-z]+$`)

// IsLogKey reports whether a listed key is a server access log object.
func IsLogKey(key string) bool { return logKey.MatchString(key) }

// maxLine bounds one record. Long keys and user agents stay well below it.
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

// Decode reads one log object and parses every line. S3 writes access logs
// as plain text; a gzipped object (for example one copied and compressed by
// hand) is also accepted, detected by its magic bytes. Unparseable lines are
// skipped and reported through a *LineError; I/O and gzip errors return no
// entries.
func Decode(_ string, r io.Reader) ([]Entry, error) {
	br := bufio.NewReader(r)
	var src io.Reader = br
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
		if strings.TrimSpace(line) == "" {
			continue
		}
		e, err := Parse(line)
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
