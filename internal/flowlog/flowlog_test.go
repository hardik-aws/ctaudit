package flowlog

import (
	"bytes"
	"compress/gzip"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testKey = "AWSLogs/111122223333/vpcflowlogs/us-east-1/2026/09/20/111122223333_vpcflowlogs_us-east-1_fl-0123456789abcdef0_20260920T1005Z_abcd1234.log.gz"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestDecodeDefaultV2(t *testing.T) {
	got, err := Decode(testKey, bytes.NewReader(gzipped(t, fixture(t, "default-v2.log"))))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 11 {
		t.Fatalf("entries = %d, want 11", len(got))
	}
	e := got[0]
	if e.Version != 2 || e.AccountID != "111122223333" || e.InterfaceID != "eni-0a1b2c3d4e5f60718" ||
		e.SrcAddr != addr("198.51.100.7") || e.DstAddr != addr("10.0.1.10") ||
		e.SrcPort != 51544 || e.DstPort != 443 || e.Protocol != 6 || e.Packets != 12 || e.Bytes != 5120 ||
		!e.Start.Equal(time.Unix(1789898400, 0)) || !e.End.Equal(time.Unix(1789898460, 0)) ||
		e.Start.Location() != time.UTC || e.Action != "ACCEPT" || e.LogStatus != StatusOK {
		t.Fatalf("first entry: %+v", e)
	}
	// Fields the default format does not carry are unknown.
	if e.VPCID != "" || e.TCPFlags != -1 || e.TrafficPath != -1 || e.PktSrcAddr.IsValid() || e.FlowDirection != "" {
		t.Fatalf("absent fields not unknown: %+v", e)
	}
	if e.Source() != e.SrcAddr || e.Dest() != e.DstAddr || e.Service() != "443/tcp" || e.ProtocolName() != "tcp" {
		t.Fatalf("derived: source %v dest %v service %q proto %q", e.Source(), e.Dest(), e.Service(), e.ProtocolName())
	}
	if icmp := got[7]; icmp.Service() != "icmp" || icmp.SrcPort != 0 || icmp.DstPort != 0 {
		t.Fatalf("icmp: %+v service %q", icmp, icmp.Service())
	}
	if v6 := got[8]; !v6.SrcAddr.Is6() || v6.DstAddr != addr("fd00::20") || v6.Service() != "5432/tcp" {
		t.Fatalf("ipv6: %+v", v6)
	}
	nd := got[9]
	if nd.LogStatus != StatusNoData || nd.SrcAddr.IsValid() || nd.SrcPort != -1 || nd.Protocol != -1 ||
		nd.Bytes != 0 || nd.Action != "" || nd.Start.IsZero() || nd.Service() != "" {
		t.Fatalf("NODATA row: %+v", nd)
	}
	if got[10].LogStatus != StatusSkipData {
		t.Fatalf("SKIPDATA row: %+v", got[10])
	}
}

func TestDecodeCustomV5(t *testing.T) {
	// Plain text: Decode sniffs gzip itself.
	got, err := Decode(testKey, bytes.NewReader(fixture(t, "custom-v5.log")))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("entries = %d, want 5", len(got))
	}
	nat := got[0]
	if nat.Version != 5 || nat.VPCID != "vpc-0123456789abcdef0" || nat.SubnetID != "subnet-0aaa1111bbbb2222c" ||
		nat.InstanceID != "" || nat.InterfaceID != "eni-0123456789abcdef0" || nat.Type != "IPv4" ||
		nat.Bytes != 3000000 || nat.Packets != 2100 || nat.TCPFlags != 3 || nat.Region != "us-east-1" ||
		nat.AZID != "use1-az1" || nat.PktSrcAWSService != "" || nat.PktDstAWSService != "S3" ||
		nat.FlowDirection != "egress" || nat.TrafficPath != 8 {
		t.Fatalf("custom fields: %+v", nat)
	}
	if nat.SrcAddr != addr("10.0.0.200") || nat.Source() != addr("10.0.1.5") || nat.Dest() != addr("52.94.133.131") {
		t.Fatalf("pkt addresses: src %v source %v dest %v", nat.SrcAddr, nat.Source(), nat.Dest())
	}
	ssh := got[1]
	if ssh.InstanceID != "i-0123456789abcdef0" || ssh.FlowDirection != "ingress" || ssh.TrafficPath != -1 || ssh.TCPFlags != 2 {
		t.Fatalf("ssh: %+v", ssh)
	}
	if got[3].Type != "IPv6" || got[4].LogStatus != StatusNoData {
		t.Fatalf("v6 %+v / nodata %+v", got[3], got[4])
	}
}

func TestStreamMatchesDecode(t *testing.T) {
	n := 0
	if err := Stream(testKey, bytes.NewReader(fixture(t, "default-v2.log")), func(Entry) { n++ }); err != nil {
		t.Fatal(err)
	}
	if n != 11 {
		t.Fatalf("Stream emitted %d, want 11", n)
	}
}

func TestDecodeLineErrors(t *testing.T) {
	in := "version srcaddr dstaddr start action\n" +
		"2 10.0.0.1 10.0.0.2 1789898400 ACCEPT\n" +
		"2 10.0.0.1 10.0.0.2 1789898400\n" +
		"2 10.0.0.1 10.0.0.2 1789898400 ACCEPT extra\n" +
		"2 10.0.0.1 not-an-ip-SECRET 1789898400 ACCEPT\n" +
		"\n"
	got, err := Decode(testKey, strings.NewReader(in))
	var le *LineError
	if !errors.As(err, &le) || le.Bad != 3 || len(got) != 1 {
		t.Fatalf("got %d entries, err %v", len(got), err)
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error quotes record contents: %v", err)
	}
}

func TestDecodeObjectErrors(t *testing.T) {
	for name, in := range map[string]string{
		"missing header": "2 111122223333 eni-1 10.0.0.1 10.0.0.2 1 2 6 1 40 1789898400 1789898460 ACCEPT OK\n",
		"no start field": "version srcaddr dstaddr action\n2 10.0.0.1 10.0.0.2 ACCEPT\n",
		"corrupt gzip":   "\x1f\x8bxx",
	} {
		got, err := Decode(testKey, strings.NewReader(in))
		if err == nil || got != nil {
			t.Errorf("%s: got %d entries, err %v; want an object error", name, len(got), err)
		}
	}
	if got, err := Decode(testKey, strings.NewReader("")); err != nil || len(got) != 0 {
		t.Errorf("empty object: %d entries, err %v", len(got), err)
	}
	got, err := Decode(strings.Replace(testKey, ".log.gz", ".log.parquet", 1), strings.NewReader("PAR1"))
	if !errors.Is(err, ErrParquet) || got != nil {
		t.Errorf("parquet: %d entries, err %v", len(got), err)
	}
}

func TestParseHeaderToleratesBraces(t *testing.T) {
	h, err := ParseHeader("${version} ${srcaddr} ${dstaddr} ${start} ${new-future-field}")
	if err != nil {
		t.Fatal(err)
	}
	e, err := h.Parse("5 10.0.0.1 10.0.0.2 1789898400 whatever")
	if err != nil || e.Version != 5 || e.SrcAddr != addr("10.0.0.1") || e.Start.Unix() != 1789898400 {
		t.Fatalf("entry %+v, err %v", e, err)
	}
}

func TestIsLogKey(t *testing.T) {
	for key, want := range map[string]bool{
		testKey: true,
		strings.Replace(testKey, ".log.gz", ".log.parquet", 1):               true,
		"AWSLogs/111122223333/vpcflowlogs/us-east-1/2026/09/20/":             false,
		"AWSLogs/111122223333/vpcflowlogs/us-east-1/2026/09/20/readme.txt":   false,
		"AWSLogs/111122223333/vpcflowlogs/us-east-1/2026/09/20/other.log.gz": false,
	} {
		if IsLogKey(key) != want {
			t.Errorf("IsLogKey(%q) != %v", key, want)
		}
	}
}

func TestProtocolName(t *testing.T) {
	for proto, want := range map[int]string{6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6", 47: "gre", 99: "99", -1: ""} {
		if got := (Entry{Protocol: proto}).ProtocolName(); got != want {
			t.Errorf("ProtocolName(%d) = %q, want %q", proto, got, want)
		}
	}
}
