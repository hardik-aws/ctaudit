package elblog

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	albFixedResponse = `http 2026-09-23T07:15:26.379899Z app/k8s-tileserver-617dd1df30/98e3a879de9d6b42 216.180.246.224:21790 - -1 -1 -1 404 - 127 162 "GET http://k8s-tileserver-617dd1df30-606955064.us-east-1.elb.amazonaws.com:80/ HTTP/1.0" "Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; +https://www.nokia.com/genomecrawler)" - - - "Root=1-6ab37c8e-5afd1aca560fd3a825162993" "-" "-" 0 2026-09-23T07:15:26.379000Z "fixed-response" "-" "-" "-" "-" "-" "-" TID_558e26a7adede44b9fdb98006014afcf "-" "-" "-" 100.51.96.60 "-" "-"`
	albForward       = `https 2026-09-23T07:15:47.805298Z app/k8s-tileserver-617dd1df30/98e3a879de9d6b42 78.190.26.165:5815 10.20.20.37:80 0.001 0.003 0.000 200 200 153 3860 "GET https://tile-staging.terrastride.com:443/data/roads_trails_merged-trails-z18_v2.json HTTP/1.1" "Dart/3.11 (dart:io)" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:702656214742:targetgroup/k8s-tileserv-tileserv-8b701414d0/ce5353cc7101de6d "Root=1-6ab37ca3-72b3ccd0353538ac305db394" "tile-staging.terrastride.com" "arn:aws:acm:us-east-1:702656214742:certificate/34ecc395-417d-479a-b9e3-2c03c1047f42" 2 2026-09-23T07:15:47.801000Z "forward" "-" "-" "10.20.20.37:80" "200" "-" "-" TID_d7917035eabacb42bea251b01fb60ab4 "-" "-" "-" 100.51.96.60 "-" "-"`
	albMalformed     = `http 2026-09-23T07:17:32.454551Z app/k8s-tileserver-617dd1df30/98e3a879de9d6b42 216.180.246.224:25824 - -1 -1 -1 400 - 0 272 "- http://k8s-tileserver-617dd1df30-606955064.us-east-1.elb.amazonaws.com:80- -" "-" - - - "-" "-" "-" - 2026-09-23T07:17:31.697000Z "-" "-" "-" "-" "-" "-" "-" TID_7d15a1935077a44b91952330c3dc3ed8 "-" "-" "-" 100.51.96.60 "-" "-"`

	nlbLine     = `tls 2.0 2018-12-20T02:59:40 net/my-network-loadbalancer/c6e77e28c25b2234 g3d4b5e8bb8464cd 72.21.218.154:51341 172.100.100.185:443 5 2 98 246 - arn:aws:acm:us-east-2:671290407336:certificate/2a108f19-aded-46b0-8493-c63eb1ef4a99 - ECDHE-RSA-AES128-SHA tlsv12 - my-network-loadbalancer-c6e77e28c25b2234.elb.us-east-2.amazonaws.com - - - 2018-12-20T02:59:30`
	classicLine = `2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.38.0" - -`

	albKey     = "AWSLogs/702656214742/elasticloadbalancing/us-east-1/2026/09/23/702656214742_elasticloadbalancing_us-east-1_app.k8s-tileserver-617dd1df30.98e3a879de9d6b42_20260923T0715Z_100.51.96.60_4k2a9x1b.log.gz"
	nlbKey     = "AWSLogs/671290407336/elasticloadbalancing/us-east-2/2018/12/20/671290407336_elasticloadbalancing_us-east-2_net.my-network-loadbalancer.c6e77e28c25b2234_20181220T0300Z_1mweux1s.log.gz"
	classicKey = "logs/AWSLogs/123456789012/elasticloadbalancing/us-west-2/2015/05/13/123456789012_elasticloadbalancing_us-west-2_my-loadbalancer_20150513T2340Z_172.160.001.192_20sg8hgm.log"
)

func approx(a, b float64) bool { d := a - b; return d < 1e-9 && d > -1e-9 }

func TestParseALBForward(t *testing.T) {
	e, err := ParseALB(albForward)
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string][2]string{
		"Type":        {e.Type, "https"},
		"LB":          {e.LB, "app/k8s-tileserver-617dd1df30/98e3a879de9d6b42"},
		"ClientIP":    {e.ClientIP, "78.190.26.165"},
		"ClientPort":  {e.ClientPort, "5815"},
		"Target":      {e.Target, "10.20.20.37:80"},
		"ELBStatus":   {e.ELBStatus, "200"},
		"Method":      {e.Method, "GET"},
		"Host":        {e.Host, "tile-staging.terrastride.com"},
		"Path":        {e.Path, "/data/roads_trails_merged-trails-z18_v2.json"},
		"Protocol":    {e.Protocol, "HTTP/1.1"},
		"UserAgent":   {e.UserAgent, "Dart/3.11 (dart:io)"},
		"SSLCipher":   {e.SSLCipher, "ECDHE-RSA-AES128-GCM-SHA256"},
		"SSLProtocol": {e.SSLProtocol, "TLSv1.2"},
		"DomainName":  {e.DomainName, "tile-staging.terrastride.com"},
		"Rule":        {e.MatchedRulePriority, "2"},
		"Actions":     {e.Actions, "forward"},
		"TargetList":  {e.TargetList, "10.20.20.37:80"},
		"TargetCodes": {e.TargetStatusList, "200"},
		"ConnTraceID": {e.ConnTraceID, "TID_d7917035eabacb42bea251b01fb60ab4"},
		"RedirectURL": {e.RedirectURL, ""},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", name, c[0], c[1])
		}
	}
	if e.Kind != ALB || e.ReceivedBytes != 153 || e.SentBytes != 3860 {
		t.Errorf("kind/bytes = %s %d %d", e.Kind, e.ReceivedBytes, e.SentBytes)
	}
	if !approx(e.Latency, 0.004) {
		t.Errorf("Latency = %v, want 0.004", e.Latency)
	}
	want := time.Date(2026, 9, 23, 7, 15, 47, 805298000, time.UTC)
	if !e.Time.Equal(want) {
		t.Errorf("Time = %v, want %v", e.Time, want)
	}
	if !strings.HasSuffix(e.TargetGroupARN, "ce5353cc7101de6d") {
		t.Errorf("TargetGroupARN = %q", e.TargetGroupARN)
	}
}

func TestParseALBFixedResponse(t *testing.T) {
	e, err := ParseALB(albFixedResponse)
	if err != nil {
		t.Fatal(err)
	}
	if e.Target != "" || e.TargetStatus != "" || e.ELBStatus != "404" {
		t.Errorf("target/status = %q %q %q", e.Target, e.TargetStatus, e.ELBStatus)
	}
	if e.Latency != -1 || e.RequestTime != -1 {
		t.Errorf("Latency = %v, want -1", e.Latency)
	}
	if e.Host != "k8s-tileserver-617dd1df30-606955064.us-east-1.elb.amazonaws.com" || e.Path != "/" {
		t.Errorf("host/path = %q %q", e.Host, e.Path)
	}
	if e.Actions != "fixed-response" || e.SSLCipher != "" {
		t.Errorf("actions/cipher = %q %q", e.Actions, e.SSLCipher)
	}
	if !strings.Contains(e.UserAgent, "GenomeCrawlerd") {
		t.Errorf("UserAgent = %q", e.UserAgent)
	}
}

func TestParseALBMalformedRequest(t *testing.T) {
	e, err := ParseALB(albMalformed)
	if err != nil {
		t.Fatal(err)
	}
	if e.Method != "" || e.Protocol != "" || e.ELBStatus != "400" {
		t.Errorf("method/proto/status = %q %q %q", e.Method, e.Protocol, e.ELBStatus)
	}
	if e.URL != "http://k8s-tileserver-617dd1df30-606955064.us-east-1.elb.amazonaws.com:80-" {
		t.Errorf("URL = %q", e.URL)
	}
	if e.Host != "k8s-tileserver-617dd1df30-606955064.us-east-1.elb.amazonaws.com" {
		t.Errorf("Host = %q", e.Host)
	}
	if e.UserAgent != "" || e.MatchedRulePriority != "" {
		t.Errorf("ua/rule = %q %q", e.UserAgent, e.MatchedRulePriority)
	}
}

func TestParseNLB(t *testing.T) {
	e, err := ParseNLB(nlbLine)
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != NLB || e.Type != "tls" || e.LB != "net/my-network-loadbalancer/c6e77e28c25b2234" {
		t.Errorf("kind/type/lb = %s %s %s", e.Kind, e.Type, e.LB)
	}
	if e.ClientIP != "72.21.218.154" || e.Target != "172.100.100.185:443" || e.Listener != "g3d4b5e8bb8464cd" {
		t.Errorf("client/target/listener = %s %s %s", e.ClientIP, e.Target, e.Listener)
	}
	if !approx(e.Latency, 0.005) || !approx(e.TLSHandshakeTime, 0.002) {
		t.Errorf("latency/handshake = %v %v", e.Latency, e.TLSHandshakeTime)
	}
	if e.ReceivedBytes != 98 || e.SentBytes != 246 {
		t.Errorf("bytes = %d %d", e.ReceivedBytes, e.SentBytes)
	}
	if e.SSLCipher != "ECDHE-RSA-AES128-SHA" || e.SSLProtocol != "tlsv12" {
		t.Errorf("tls = %s %s", e.SSLCipher, e.SSLProtocol)
	}
	if e.HostOrSNI() != "my-network-loadbalancer-c6e77e28c25b2234.elb.us-east-2.amazonaws.com" {
		t.Errorf("HostOrSNI = %s", e.HostOrSNI())
	}
	if !e.Time.Equal(time.Date(2018, 12, 20, 2, 59, 40, 0, time.UTC)) {
		t.Errorf("Time = %v", e.Time)
	}
}

func TestParseClassic(t *testing.T) {
	e, err := ParseClassic(classicLine)
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != Classic || e.Type != "http" || e.LB != "my-loadbalancer" {
		t.Errorf("kind/type/lb = %s %s %s", e.Kind, e.Type, e.LB)
	}
	if e.Host != "www.example.com" || e.Path != "/" || e.UserAgent != "curl/7.38.0" {
		t.Errorf("host/path/ua = %s %s %s", e.Host, e.Path, e.UserAgent)
	}
	if !approx(e.Latency, 0.000073+0.001048+0.000057) || e.SentBytes != 29 {
		t.Errorf("latency/sent = %v %d", e.Latency, e.SentBytes)
	}
}

func TestParseRejectsShortLines(t *testing.T) {
	for name, fn := range map[string]func(string) (Entry, error){
		"alb": ParseALB, "nlb": ParseNLB, "classic": ParseClassic,
	} {
		if _, err := fn("too short"); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := ParseALB(strings.Replace(albForward, "2026-09-23T07:15:47.805298Z", "yesterday", 1)); err == nil {
		t.Error("expected bad time error")
	}
}

func TestFieldsQuotesAndEscapes(t *testing.T) {
	got := fields(`a "b c" "d \"e\"" "" f`)
	want := []string{"a", "b c", `d "e"`, "", "f"}
	if len(got) != len(want) {
		t.Fatalf("fields = %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitURL(t *testing.T) {
	cases := []struct{ in, host, path string }{
		{"https://Example.com:443/a/b?x=1", "example.com", "/a/b"},
		{"http://[2001:db8::1]:80/p", "2001:db8::1", "/p"},
		{"http://host.example:80-", "host.example", ""},
		{"/relative?q", "", "/relative"},
		{"", "", ""},
	}
	for _, c := range cases {
		h, p := splitURL(c.in)
		if h != c.host || p != c.path {
			t.Errorf("splitURL(%q) = %q %q, want %q %q", c.in, h, p, c.host, c.path)
		}
	}
}

func TestKeyHelpers(t *testing.T) {
	cases := []struct {
		key  string
		kind Kind
		name string
	}{
		{albKey, ALB, "k8s-tileserver-617dd1df30"},
		{nlbKey, NLB, "my-network-loadbalancer"},
		{classicKey, Classic, "my-loadbalancer"},
	}
	for _, c := range cases {
		if got := KindFromKey(c.key); got != c.kind {
			t.Errorf("KindFromKey(%s) = %q, want %q", c.key, got, c.kind)
		}
		if got := LBNameFromKey(c.key); got != c.name {
			t.Errorf("LBNameFromKey = %q, want %q", got, c.name)
		}
		if !IsLogKey(c.key) {
			t.Errorf("IsLogKey(%s) = false", c.key)
		}
	}
	for _, k := range []string{
		"AWSLogs/702656214742/ELBAccessLogTestFile",
		"AWSLogs/702656214742/CloudTrail/us-east-1/2026/09/23/702656214742_CloudTrail_us-east-1_20260923T0000Z_abc.json.gz",
		strings.TrimSuffix(albKey, ".log.gz") + ".txt",
	} {
		if IsLogKey(k) {
			t.Errorf("IsLogKey(%s) = true", k)
		}
	}
}

func TestParseKind(t *testing.T) {
	for in, want := range map[string]Kind{"ALB": ALB, "net": NLB, "elb": Classic, "classic": Classic} {
		got, err := ParseKind(in)
		if err != nil || got != want {
			t.Errorf("ParseKind(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseKind("gwlb"); err == nil {
		t.Error("expected error")
	}
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestDecodeGzipALB(t *testing.T) {
	body := gz(t, albFixedResponse+"\n"+albForward+"\n\n"+albMalformed+"\n")
	got, err := Decode(albKey, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("entries = %d, want 3", len(got))
	}
}

func TestDecodePlainClassic(t *testing.T) {
	got, err := Decode(classicKey, strings.NewReader(classicLine+"\r\n"))
	if err != nil || len(got) != 1 {
		t.Fatalf("got %d entries, err %v", len(got), err)
	}
}

func TestDecodeReportsBadLines(t *testing.T) {
	body := gz(t, albForward+"\ngarbage line\n"+albForward+"\n")
	got, err := Decode(albKey, bytes.NewReader(body))
	var le *LineError
	if !errors.As(err, &le) || le.Bad != 1 {
		t.Fatalf("err = %v, want LineError with 1 bad line", err)
	}
	if len(got) != 2 {
		t.Errorf("entries = %d, want 2", len(got))
	}
}

func TestDecodeRejectsUnknownKeyAndBadGzip(t *testing.T) {
	if _, err := Decode("foo.log", strings.NewReader(classicLine)); err == nil {
		t.Error("expected error for non-ELB key")
	}
	if _, err := Decode(albKey, bytes.NewReader([]byte{0x1f, 0x8b, 0, 0})); err == nil {
		t.Error("expected gzip error")
	}
}

const (
	connKey = "AWSLogs/702656214742/elasticloadbalancing/us-east-1/2026/09/23/" +
		"conn_log_702656214742_elasticloadbalancing_us-east-1_app.k8s-tileserver-617dd1df30.98e3a879de9d6b42_20260923T0715Z_54.81.166.60_57hw2gm1.log.gz"
	connTLS    = `2026-09-23T07:11:27.691358Z 49.36.71.40 64326 443 TLSv1.2 ECDHE-ECDSA-AES128-GCM-SHA256 0.337 "-" - - Success TID_9f39d9aa6a47774d97089313f949866b secp256r1 app/k8s-tileserver-617dd1df30/98e3a879de9d6b42 3.228.177.57`
	connPlain  = `2026-09-23T07:11:32.882572Z 147.185.132.159 61814 80 - - - "-" - - - TID_14bdaac20df9aa4ca3139b3168e4e071 - app/k8s-tileserver-617dd1df30/98e3a879de9d6b42 3.228.177.57`
	connFailed = `2026-09-23T07:12:01.000000Z 198.51.100.7 50000 443 - - - "-" - - - TID_aa - app/k8s-tileserver-617dd1df30/98e3a879de9d6b42 3.228.177.57`
)

func TestParseALBConn(t *testing.T) {
	e, err := ParseALBConn(connTLS)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Conn || e.Kind != ALB {
		t.Errorf("Conn=%v Kind=%q", e.Conn, e.Kind)
	}
	checks := map[string][2]string{
		"ClientIP":        {e.ClientIP, "49.36.71.40"},
		"ClientPort":      {e.ClientPort, "64326"},
		"Listener":        {e.Listener, "443"},
		"SSLProtocol":     {e.SSLProtocol, "TLSv1.2"},
		"SSLCipher":       {e.SSLCipher, "ECDHE-ECDSA-AES128-GCM-SHA256"},
		"TLSVerifyStatus": {e.TLSVerifyStatus, "Success"},
		"ConnTraceID":     {e.ConnTraceID, "TID_9f39d9aa6a47774d97089313f949866b"},
		"TLSKeyExchange":  {e.TLSKeyExchange, "secp256r1"},
		"LB":              {e.LB, "app/k8s-tileserver-617dd1df30/98e3a879de9d6b42"},
		"CertSubject":     {e.ClientCertSubject, ""},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", name, c[0], c[1])
		}
	}
	if e.TLSHandshakeTime != 0.337 {
		t.Errorf("TLSHandshakeTime = %v", e.TLSHandshakeTime)
	}
	if e.Latency != -1 || e.HandshakeFailed() {
		t.Errorf("Latency=%v HandshakeFailed=%v", e.Latency, e.HandshakeFailed())
	}

	p, err := ParseALBConn(connPlain)
	if err != nil {
		t.Fatal(err)
	}
	if p.SSLProtocol != "" || p.TLSHandshakeTime != -1 || p.HandshakeFailed() {
		t.Errorf("plain: proto=%q hs=%v failed=%v", p.SSLProtocol, p.TLSHandshakeTime, p.HandshakeFailed())
	}
	f, err := ParseALBConn(connFailed)
	if err != nil || !f.HandshakeFailed() {
		t.Errorf("failed handshake not detected: %v", err)
	}
	if _, err := ParseALBConn("2026-09-23T07:11:27Z 1.2.3.4 1"); err == nil {
		t.Error("expected error for short line")
	}
}

func TestConnLogKey(t *testing.T) {
	if !IsConnLogKey(connKey) || IsConnLogKey(albKey) {
		t.Errorf("IsConnLogKey wrong")
	}
	if !IsLogKey(connKey) || KindFromKey(connKey) != ALB {
		t.Errorf("conn key: IsLogKey=%v Kind=%q", IsLogKey(connKey), KindFromKey(connKey))
	}
	if got := LBNameFromKey(connKey); got != "k8s-tileserver-617dd1df30" {
		t.Errorf("LBNameFromKey = %q", got)
	}
}

func TestDecodeConnLog(t *testing.T) {
	body := gz(t, connTLS+"\n"+connPlain+"\n"+connFailed+"\n")
	got, err := Decode(connKey, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !got[0].Conn {
		t.Fatalf("entries = %d, want 3 connection records", len(got))
	}
}
