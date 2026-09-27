package s3log

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
	"time"
)

const owner = "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"

var (
	// docsExample is the example record from the AWS server access log
	// format documentation (note the upper-case TLSV1.2).
	docsExample = owner + ` amzn-s3-demo-bucket1 [06/Feb/2019:00:00:38 +0000] 192.0.2.3 ` + owner + ` 3E57427F3EXAMPLE REST.GET.VERSIONING - "GET /amzn-s3-demo-bucket1?versioning HTTP/1.1" 200 - 113 - 7 - "-" "S3Console/0.4" - s9lzHYrFp76ZVxRcpX9+5cjAnEH2ROuNkd2BHfIa6UkFVdtjf5mKR3/eTPFvsiP/XV/VLi31234= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader amzn-s3-demo-bucket1.s3.us-west-1.amazonaws.com TLSV1.2 arn:aws:s3:us-west-1:123456789012:accesspoint/example-AP Yes`

	anonGet = owner + ` web-assets [20/Sep/2026:10:15:02 +0000] 203.0.113.9 - 3E57427F3EXAMPLF REST.GET.OBJECT img/logo.png "GET /img/logo.png HTTP/1.1" 200 - 5120 5120 12 11 "https://www.example.com/page?session=SECRETREF#top" "Mozilla/5.0 (X11; Linux x86_64)" - hostIdSECRET= - ECDHE-RSA-AES128-GCM-SHA256 - web-assets.s3.us-east-1.amazonaws.com TLSv1.2 - -`

	presignedGet = owner + ` data-bucket [20/Sep/2026:10:16:40 +0000] 198.51.100.7 arn:aws:iam::111122223333:user/alice 4B1C2D3E4F5A6B7C REST.GET.OBJECT reports/2026/q3.csv "GET /reports/2026/q3.csv?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260920%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=SECRETSIG HTTP/1.1" 200 - 1048576 1048576 85 40 "-" "aws-sdk-go-v2/1.30.0" 3HL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY hostIdSECRET= SigV4 ECDHE-RSA-AES128-GCM-SHA256 QueryString data-bucket.s3.us-east-1.amazonaws.com TLSv1.3 - -`

	anonPutHTTP = owner + ` data-bucket [20/Sep/2026:10:20:00 +0000] 192.0.2.44 - 5C6D7E8F9A0B1C2D REST.PUT.OBJECT uploads/shell.php "PUT /uploads/shell.php HTTP/1.1" 200 - - 2048 30 29 "-" "curl/8.4.0" - hostIdSECRET= - - - data-bucket.s3.amazonaws.com - - -`

	denied = owner + ` data-bucket [20/Sep/2026:10:21:00 +0000] 192.0.2.50 arn:aws:sts::444455556666:assumed-role/scanner/i-0abc 6D7E8F9A0B1C2D3E REST.GET.OBJECT secrets/db.env "GET /secrets/db.env HTTP/1.1" 403 AccessDenied 243 - 9 - "-" "Boto3/1.34.0 Python/3.12" - hostIdSECRET= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader data-bucket.s3.us-east-1.amazonaws.com TLSv1.2 - -`

	policyChange = owner + ` data-bucket [20/Sep/2026:10:22:00 +0000] 198.51.100.7 arn:aws:iam::111122223333:user/alice 7E8F9A0B1C2D3E4F REST.PUT.BUCKETPOLICY - "PUT /?policy HTTP/1.1" 204 - - 512 60 - "-" "aws-cli/2.17.0" - hostIdSECRET= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader data-bucket.s3.us-east-1.amazonaws.com TLSv1.2 - -`

	batchDelete = owner + ` data-bucket [20/Sep/2026:10:23:00 +0000] 198.51.100.7 arn:aws:iam::111122223333:user/alice 8F9A0B1C2D3E4F5A BATCH.DELETE.OBJECT logs/app-1.log - 204 - - - - - - - - hostIdSECRET= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader data-bucket.s3.us-east-1.amazonaws.com TLSv1.2 - -`

	legacyClient = owner + ` data-bucket [20/Sep/2026:10:24:00 +0000] 192.0.2.60 arn:aws:iam::111122223333:user/legacy 9A0B1C2D3E4F5A6B REST.HEAD.OBJECT index.html "HEAD /index.html HTTP/1.1" 200 - - 1024 5 4 "-" "S3Browser/10" - hostIdSECRET= SigV2 AES128-SHA AuthHeader data-bucket.s3.amazonaws.com TLSv1 - -`

	// oldFormat predates the sig_version and later fields.
	oldFormat = owner + ` old-bucket [01/Mar/2016:08:00:00 +0000] 192.0.2.70 - A1B2C3D4E5F6A7B8 REST.GET.OBJECT a.txt "GET /old-bucket/a.txt HTTP/1.1" 200 - 10 10 3 2 "-" "Wget/1.12" -`

	// extraFields carries fields a future format might append.
	extraFields = anonGet + ` future-field-1 "future quoted"`
)

func mustParse(t *testing.T, line string) Entry {
	t.Helper()
	e, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, line)
	}
	return e
}

func TestParseDocsExample(t *testing.T) {
	e := mustParse(t, docsExample)
	if !e.Time.Equal(time.Date(2019, 2, 6, 0, 0, 38, 0, time.UTC)) || e.Bucket != "amzn-s3-demo-bucket1" || e.RemoteIP != "192.0.2.3" {
		t.Fatalf("basic fields: %+v", e)
	}
	if e.Requester != owner || e.RequestID != "3E57427F3EXAMPLE" || e.Operation != "REST.GET.VERSIONING" || e.Key != "" {
		t.Fatalf("request ids: %+v", e)
	}
	if e.Method != "GET" || e.Path != "/amzn-s3-demo-bucket1" || e.Proto != "HTTP/1.1" || e.Status != 200 || e.ErrorCode != "" {
		t.Fatalf("request line: %+v", e)
	}
	if e.BytesSent != 113 || e.ObjectSize != 0 || e.TotalTimeMS != 7 || e.TurnaroundMS != -1 {
		t.Fatalf("numbers: %+v", e)
	}
	if e.UserAgent != "S3Console/0.4" || e.Referer != "" || e.SigVersion != "SigV4" || e.AuthType != "AuthHeader" ||
		e.CipherSuite != "ECDHE-RSA-AES128-GCM-SHA256" || e.HostHeader != "amzn-s3-demo-bucket1.s3.us-west-1.amazonaws.com" {
		t.Fatalf("client fields: %+v", e)
	}
	if e.TLSVersion != "TLSv1.2" || e.AccessPointARN != "arn:aws:s3:us-west-1:123456789012:accesspoint/example-AP" || !e.ACLRequired || e.PlainHTTP {
		t.Fatalf("tail fields: %+v", e)
	}
}

func TestParseClassifies(t *testing.T) {
	a := mustParse(t, anonGet)
	if a.Requester != "" || a.Principal() != Anonymous || !a.IsObjectRead() || !a.Success() || a.Referer != "https://www.example.com/page" {
		t.Fatalf("anonGet: %+v", a)
	}
	p := mustParse(t, presignedGet)
	if p.Path != "/reports/2026/q3.csv" || p.AuthType != "QueryString" || p.TLSVersion != "TLSv1.3" || p.Principal() != "arn:aws:iam::111122223333:user/alice" {
		t.Fatalf("presignedGet: %+v", p)
	}
	w := mustParse(t, anonPutHTTP)
	if !w.PlainHTTP || !w.IsObjectWrite() || w.BytesSent != 0 || w.ObjectSize != 2048 || w.TLSVersion != "" {
		t.Fatalf("anonPutHTTP: %+v", w)
	}
	d := mustParse(t, denied)
	if !d.Denied() || !d.IsError() || d.Status != 403 || d.ErrorCode != "AccessDenied" || d.StatusClass() != "4xx" {
		t.Fatalf("denied: %+v", d)
	}
	c := mustParse(t, policyChange)
	if !c.IsAccessChange() || c.Status != 204 || c.Path != "/" || c.Key != "" {
		t.Fatalf("policyChange: %+v", c)
	}
	b := mustParse(t, batchDelete)
	if !b.IsObjectDelete() || b.Method != "" || b.Status != 204 || b.TotalTimeMS != -1 || b.UserAgent != "" {
		t.Fatalf("batchDelete: %+v", b)
	}
	l := mustParse(t, legacyClient)
	if !l.WeakTLS() || !l.SigV2() || l.IsObjectWrite() {
		t.Fatalf("legacyClient: %+v", l)
	}
	o := mustParse(t, oldFormat)
	if o.TLSVersion != "" || o.PlainHTTP || o.TotalTimeMS != 3 || o.UserAgent != "Wget/1.12" || o.SigVersion != "" {
		t.Fatalf("oldFormat: %+v", o)
	}
	if x := mustParse(t, extraFields); x != a {
		t.Fatalf("extra fields changed the entry:\n%+v\n%+v", x, a)
	}
	if (Entry{}).StatusClass() != "other" || (Entry{Status: 503}).StatusClass() != "5xx" {
		t.Fatal("StatusClass")
	}
	if (Entry{Operation: "REST.POST.MULTI_OBJECT_DELETE"}).IsMultiDelete() != true {
		t.Fatal("IsMultiDelete")
	}
	if (Entry{Operation: "WEBSITE.GET.OBJECT"}).IsObjectRead() {
		t.Fatal("website reads are not object reads")
	}
}

func TestParseDropsSecrets(t *testing.T) {
	for _, line := range []string{docsExample, anonGet, presignedGet, anonPutHTTP, denied, policyChange, batchDelete, legacyClient, oldFormat} {
		s := fmt.Sprintf("%+v", mustParse(t, line))
		for _, secret := range []string{"SECRET", "X-Amz", "AKIA", "hostId", "s9lzHY", "3HL4kq", "versioning", "session="} {
			if strings.Contains(s, secret) {
				t.Errorf("entry leaks %q: %s", secret, s)
			}
		}
		if line != docsExample && strings.Contains(s, owner) {
			t.Errorf("entry keeps the bucket owner: %s", s)
		}
	}
}

func TestParseRejectsBadLines(t *testing.T) {
	for _, line := range []string{
		"not a log line",
		owner + ` b [20/Sep/2026:10:15:02 +0000] 1.2.3.4 - id REST.GET.OBJECT k "GET / HTTP/1.1"`,
		owner + ` b [bad time] 1.2.3.4 - id REST.GET.OBJECT k "GET / HTTP/1.1" 200`,
		owner + ` b [20/Sep/2026:10:15:02 +0000] 1.2.3.4 - id REST.GET.OBJECT k "GET / HTTP/1.1 200`,
	} {
		if _, err := Parse(line); err == nil {
			t.Errorf("Parse(%q) succeeded", line)
		}
	}
}

func TestDecodePlainGzipAndBadLine(t *testing.T) {
	body := anonGet + "\r\nnot a log line\n\n" + denied + "\n"
	got, err := Decode("logs/2026-09-20-10-15-02-A1B2C3D4E5F6A7B8", strings.NewReader(body))
	le, ok := err.(*LineError)
	if !ok || le.Bad != 1 || len(got) != 2 {
		t.Fatalf("plain: %d entries, err %v", len(got), err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(anonGet + "\n" + denied + "\n"))
	zw.Close()
	got, err = Decode("k", &buf)
	if err != nil || len(got) != 2 {
		t.Fatalf("gzip: %d entries, err %v", len(got), err)
	}
	if _, err := Decode("k", strings.NewReader("\x1f\x8bxx")); err == nil {
		t.Fatal("corrupt gzip must fail")
	}
}

func TestIsLogKey(t *testing.T) {
	for key, want := range map[string]bool{
		"logs/2026-09-20-10-15-02-A1B2C3D4E5F6A7B8":                                               true,
		"access-2026-09-20-10-15-02-A1B2C3D4E5F6A7B8":                                             true,
		"2026-09-20-10-15-02-A1B2C3D4E5F6A7B8":                                                    true,
		"logs/111122223333/us-east-1/data-bucket/2026/09/20/2026-09-20-10-15-02-A1B2C3D4E5F6A7B8": true,
		"logs/":                    false,
		"logs/readme.txt":          false,
		"logs/2026-09-20-10-15-02": false,
	} {
		if IsLogKey(key) != want {
			t.Errorf("IsLogKey(%q) != %v", key, want)
		}
	}
}
