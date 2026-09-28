package stats

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/flowlog"
)

var vpcT0 = time.Date(2026, 9, 20, 10, 30, 0, 0, time.UTC)

func vflow(src, dst string, sp, dp, proto int, action string, bytes int64) flowlog.Entry {
	return flowlog.Entry{
		Version: 2, AccountID: "111122223333", InterfaceID: "eni-1",
		SrcAddr: netip.MustParseAddr(src), DstAddr: netip.MustParseAddr(dst),
		SrcPort: sp, DstPort: dp, Protocol: proto, Packets: 2, Bytes: bytes,
		Start: vpcT0, End: vpcT0.Add(time.Minute), Action: action, LogStatus: flowlog.StatusOK,
		TCPFlags: -1, TrafficPath: -1,
	}
}

func TestVPCSummaryFixture(t *testing.T) {
	f, err := os.Open("../flowlog/testdata/default-v2.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := NewVPCSummary(VPCLimits{})
	err = flowlog.Stream("x_vpcflowlogs_x.log.gz", f, func(e flowlog.Entry) {
		if e.LogStatus != flowlog.StatusOK {
			s.AddStatus(e.LogStatus)
			return
		}
		s.Add(e)
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Flows != 9 || s.Accepted() != 5 || s.Rejected() != 4 || s.Bytes != 134251164 || s.Packets != 90062 ||
		s.NoData != 1 || s.SkipData != 1 {
		t.Fatalf("totals: flows %d accept %d reject %d bytes %d packets %d nodata %d skipdata %d",
			s.Flows, s.Accepted(), s.Rejected(), s.Bytes, s.Packets, s.NoData, s.SkipData)
	}
	if s.ByDstPort["443/tcp"] != 2 || s.ByProtocol["icmp"] != 1 || s.ByInterface["eni-0a1b2c3d4e5f60718"] != 5 {
		t.Fatalf("breakdowns: ports %v protocols %v interfaces %v", s.ByDstPort, s.ByProtocol, s.ByInterface)
	}
	scanner := netip.MustParseAddr("203.0.113.9")
	if s.ScanPorts.Count(scanner) != 3 || s.RejectsBySrc["203.0.113.9"] != 3 {
		t.Fatalf("scan ports = %d, rejects = %d", s.ScanPorts.Count(scanner), s.RejectsBySrc["203.0.113.9"])
	}
	x := s.Exposed["10.0.1.20:22/tcp"]
	if x == nil || x.Flows != 1 || x.Bytes != 7200 || x.Sources["203.0.113.50"] != 1 || len(s.Exposed) != 1 {
		t.Fatalf("exposed: %+v (all %v)", x, s.Exposed)
	}
	// The server's reply (443 -> 51544) is not egress; the client upload is.
	if s.EgressBytes["10.0.1.30"] != 134217728 || s.EgressBytes["10.0.1.10"] != 0 {
		t.Fatalf("egress: %v", s.EgressBytes)
	}
	if s.RejectRate() < 0.44 || s.RejectRate() > 0.45 || s.Truncated() {
		t.Fatalf("reject rate %v truncated %v", s.RejectRate(), s.Truncated())
	}
}

func TestVPCSummaryAddMerge(t *testing.T) {
	a, b := NewVPCSummary(VPCLimits{}), NewVPCSummary(VPCLimits{})
	a.Add(vflow("203.0.113.9", "10.0.1.10", 40001, 22, 6, "REJECT", 40))
	later := vflow("10.0.1.30", "198.51.100.200", 49152, 443, 6, "ACCEPT", 1000)
	later.Start = vpcT0.Add(2 * time.Hour)
	b.Add(later)
	b.Add(vflow("203.0.113.9", "10.0.1.11", 40002, 23, 6, "REJECT", 40))
	b.AddStatus(flowlog.StatusNoData)
	a.Merge(b)
	if a.Flows != 3 || a.Bytes != 1080 || a.Packets != 6 || a.NoData != 1 {
		t.Fatalf("totals %+v", a)
	}
	if !a.First.Equal(vpcT0) || !a.Last.Equal(vpcT0.Add(2*time.Hour)) {
		t.Fatalf("window %v - %v", a.First, a.Last)
	}
	if a.ByAction["REJECT"] != 2 || a.BytesByAction["ACCEPT"] != 1000 || a.RejectsBySrc["203.0.113.9"] != 2 {
		t.Fatalf("actions %v bytes %v rejects %v", a.ByAction, a.BytesByAction, a.RejectsBySrc)
	}
	h := vpcT0.Unix() / 3600
	if a.ByHour[h]["REJECT"] != 2 || a.ByHour[h+2]["ACCEPT"] != 1 {
		t.Fatalf("hours %v", a.ByHour)
	}
	if a.PairBytes["10.0.1.30 -> 198.51.100.200"] != 1000 || a.BySrc["203.0.113.9"] != 2 || a.ByDst["10.0.1.11"] != 1 {
		t.Fatalf("pairs %v src %v dst %v", a.PairBytes, a.BySrc, a.ByDst)
	}
	if a.ScanPorts.Count(netip.MustParseAddr("203.0.113.9")) != 2 || a.Sweep.Count(netip.MustParseAddr("203.0.113.9")) != 2 {
		t.Fatal("distinct trackers not merged")
	}
}

func TestVPCSummaryScanSkipsNonSYN(t *testing.T) {
	s := NewVPCSummary(VPCLimits{})
	ack := vflow("198.51.100.99", "10.0.1.5", 443, 61000, 6, "REJECT", 40)
	ack.TCPFlags = 16
	syn := vflow("198.51.100.99", "10.0.1.5", 51000, 3306, 6, "REJECT", 40)
	syn.TCPFlags = 2
	// SYN-ACK (flags 18): the answer to a SYN sent the other way, not a
	// connection attempt by this source, so it must not count either.
	synAck := vflow("198.51.100.99", "10.0.1.5", 51001, 3307, 6, "REJECT", 40)
	synAck.TCPFlags = 18
	icmp := vflow("198.51.100.99", "10.0.1.5", 0, 0, 1, "REJECT", 40)
	private := vflow("10.0.9.9", "10.0.1.5", 51000, 22, 6, "REJECT", 40)
	for _, e := range []flowlog.Entry{ack, syn, synAck, icmp, private} {
		s.Add(e)
	}
	if got := s.ScanPorts.Values(netip.MustParseAddr("198.51.100.99")); len(got) != 1 || got[0] != 3306 {
		t.Fatalf("scan ports = %v, want [3306]", got)
	}
	if s.ScanPorts.Sources() != 1 {
		t.Fatal("private sources must not count as scanners")
	}
}

func TestVPCSummaryInitiatorHeuristic(t *testing.T) {
	s := NewVPCSummary(VPCLimits{})
	// A private web server answering public clients: not egress, not a sweep.
	s.Add(vflow("10.0.1.10", "198.51.100.7", 443, 51544, 6, "ACCEPT", 5000))
	s.Add(vflow("10.0.1.10", "10.0.2.7", 443, 51544, 6, "ACCEPT", 5000))
	if len(s.EgressBytes) != 0 || s.Sweep.Sources() != 0 {
		t.Fatalf("server replies counted: egress %v sweep sources %d", s.EgressBytes, s.Sweep.Sources())
	}
	// ICMP and unknown ports count as initiated.
	s.Add(vflow("10.0.1.10", "10.0.2.8", 0, 0, 1, "ACCEPT", 84))
	s.Add(vflow("10.0.1.10", "8.8.8.8", -1, -1, 50, "ACCEPT", 100))
	if s.Sweep.Count(netip.MustParseAddr("10.0.1.10")) != 1 || s.EgressBytes["10.0.1.10"] != 100 {
		t.Fatalf("sweep %d egress %v", s.Sweep.Count(netip.MustParseAddr("10.0.1.10")), s.EgressBytes)
	}
}

func TestVPCSummaryExposedAndLegacy(t *testing.T) {
	s := NewVPCSummary(VPCLimits{})
	s.Add(vflow("192.0.2.44", "10.0.1.5", 60000, 22, 6, "ACCEPT", 5200))
	s.Add(vflow("192.0.2.45", "10.0.1.5", 60001, 22, 6, "ACCEPT", 100))
	egress := vflow("192.0.2.46", "10.0.1.5", 60002, 22, 6, "ACCEPT", 100)
	egress.FlowDirection = "egress"
	s.Add(egress)
	s.Add(vflow("192.0.2.44", "10.0.1.5", 60000, 22, 6, "REJECT", 40))
	s.Add(vflow("192.0.2.44", "fd00::5", 60000, 5432, 6, "ACCEPT", 10))
	x := s.Exposed["10.0.1.5:22/tcp"]
	if x == nil || x.Flows != 2 || x.Bytes != 5300 || len(x.Sources) != 2 || !x.First.Equal(vpcT0) {
		t.Fatalf("exposed ssh: %+v", x)
	}
	if s.Exposed["[fd00::5]:5432/tcp"] == nil {
		t.Fatalf("IPv6 key missing: %v", s.Exposed)
	}
	s.Add(vflow("203.0.113.5", "10.0.1.6", 50000, 23, 6, "ACCEPT", 10))
	s.Add(vflow("10.0.1.7", "203.0.113.6", 50000, 445, 6, "ACCEPT", 10))
	s.Add(vflow("10.0.1.7", "10.0.1.8", 50000, 445, 6, "ACCEPT", 10))
	if s.Legacy["10.0.1.6|in|23/tcp"] != 1 || s.Legacy["10.0.1.7|out|445/tcp"] != 1 || len(s.Legacy) != 2 {
		t.Fatalf("legacy: %v", s.Legacy)
	}
}

// TestVPCSummaryExposedNeedsInitiator is the controller ruling for I2: a
// flow only looks exposed when the public source looks like it started the
// conversation. A source port below the destination port looks like return
// traffic (a reply from the sensitive service back out through a NAT'd or
// misclassified path), not a new connection from the public side.
func TestVPCSummaryExposedNeedsInitiator(t *testing.T) {
	s := NewVPCSummary(VPCLimits{})
	s.Add(vflow("203.0.113.5", "10.0.0.9", 443, 5432, 6, "ACCEPT", 100))
	if len(s.Exposed) != 0 {
		t.Fatalf("return-looking traffic must not expose: %v", s.Exposed)
	}
	s.Add(vflow("203.0.113.5", "10.0.0.9", 50000, 5432, 6, "ACCEPT", 100))
	if x := s.Exposed["10.0.0.9:5432/tcp"]; x == nil || x.Flows != 1 {
		t.Fatalf("initiator-looking traffic must still expose: %+v", s.Exposed)
	}
}

func TestVPCSummaryUsesPacketAddresses(t *testing.T) {
	s := NewVPCSummary(VPCLimits{})
	nat := vflow("10.0.0.200", "52.94.133.131", 49600, 443, 6, "ACCEPT", 3000000)
	nat.PktSrcAddr, nat.PktDstAddr = netip.MustParseAddr("10.0.1.5"), netip.MustParseAddr("52.94.133.131")
	s.Add(nat)
	if s.BySrc["10.0.1.5"] != 1 || s.BySrc["10.0.0.200"] != 0 || s.EgressBytes["10.0.1.5"] != 3000000 {
		t.Fatalf("src %v egress %v", s.BySrc, s.EgressBytes)
	}
}

func TestVPCSummaryCaps(t *testing.T) {
	l := VPCLimits{MaxKeys: 2, MaxSources: 1, ScanPorts: 2, SweepHosts: 2}
	a, b := NewVPCSummary(l), NewVPCSummary(l)
	for i, src := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		a.Add(vflow(src, "10.0.1.1", 40000+i, 22, 6, "REJECT", 40))
		b.Add(vflow(src, "10.0.1.2", 40000+i, 22, 6, "ACCEPT", 40))
	}
	a.Merge(b)
	if len(a.BySrc) != 3 || a.BySrc[OtherKey] != 2 || a.Flows != 6 {
		t.Fatalf("BySrc %v flows %d", a.BySrc, a.Flows)
	}
	if len(a.Exposed) != 1 || a.ExposedDropped != 0 {
		t.Fatalf("exposed %v dropped %d", a.Exposed, a.ExposedDropped)
	}
	if x := a.Exposed["10.0.1.2:22/tcp"]; x.Flows != 3 {
		t.Fatalf("exposed flows %d", x.Flows)
	}
	if !a.ScanPorts.Truncated || !a.Truncated() {
		t.Fatal("distinct truncation not reported")
	}
	c := NewVPCSummary(l)
	c.Add(vflow("203.0.113.1", "10.0.1.1", 40000, 22, 6, "ACCEPT", 1))
	c.Add(vflow("203.0.113.1", "10.0.1.2", 40000, 22, 6, "ACCEPT", 1))
	c.Add(vflow("203.0.113.1", "10.0.1.3", 40000, 22, 6, "ACCEPT", 1))
	if len(c.Exposed) != 2 || c.ExposedDropped != 1 {
		t.Fatalf("exposed cap: %d keys, dropped %d", len(c.Exposed), c.ExposedDropped)
	}
}
