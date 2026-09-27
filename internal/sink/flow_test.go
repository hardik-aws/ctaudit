package sink

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/flowlog"
)

func TestEncoderVPC(t *testing.T) {
	start := time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC)
	x := flowlog.Entry{
		Version: 5, AccountID: "111122223333", InterfaceID: "eni-0123456789abcdef0", VPCID: "vpc-0123456789abcdef0",
		SubnetID: "subnet-0aaa1111bbbb2222c", SrcAddr: netip.MustParseAddr("10.0.0.200"), DstAddr: netip.MustParseAddr("52.94.133.131"),
		PktSrcAddr: netip.MustParseAddr("10.0.1.5"), PktDstAddr: netip.MustParseAddr("52.94.133.131"),
		SrcPort: 49600, DstPort: 443, Protocol: 6, Packets: 2100, Bytes: 3000000, Start: start, End: start.Add(time.Minute),
		Action: "ACCEPT", LogStatus: "OK", TCPFlags: 3, Type: "IPv4", Region: "us-east-1", AZID: "use1-az1",
		PktDstAWSService: "S3", FlowDirection: "egress", TrafficPath: 8,
	}
	e := Encoder{Job: "ctaudit", Subcommand: "vpc", RunID: "run-1"}
	labels, at, line := e.VPC(x)
	want := Labels{"job": "ctaudit", "subcommand": "vpc", "kind": "flow", "action": "ACCEPT", "vpc": "vpc-0123456789abcdef0"}
	if labels.key() != want.key() || !at.Equal(start) {
		t.Fatalf("labels %v at %v", labels, at)
	}
	m := decode(t, line)
	for k, v := range map[string]any{
		"kind": "flow", "run_id": "run-1", "event_time": "2026-09-20T11:00:00Z", "end_time": "2026-09-20T11:01:00Z",
		"action": "ACCEPT", "log_status": "OK", "version": float64(5), "interface_id": "eni-0123456789abcdef0",
		"src_addr": "10.0.0.200", "pkt_src_addr": "10.0.1.5", "source": "10.0.1.5", "destination": "52.94.133.131",
		"src_port": float64(49600), "dst_port": float64(443), "protocol": "tcp", "packets": float64(2100),
		"bytes": float64(3000000), "tcp_flags": float64(3), "pkt_dst_aws_service": "S3", "flow_direction": "egress",
		"traffic_path": float64(8), "az_id": "use1-az1",
	} {
		if m[k] != v {
			t.Errorf("%s = %v, want %v", k, m[k], v)
		}
	}
	if _, ok := m["instance_id"]; ok {
		t.Error("empty instance_id should be omitted")
	}
}

func TestEncoderVPCUnknownFields(t *testing.T) {
	// A default-format ICMP flow: ports are 0 (kept), flags and traffic path
	// unknown (omitted), no VPC label.
	x := flowlog.Entry{
		Version: 2, SrcAddr: netip.MustParseAddr("10.0.1.30"), DstAddr: netip.MustParseAddr("10.0.2.5"),
		SrcPort: 0, DstPort: 0, Protocol: 1, Start: time.Unix(1789898430, 0).UTC(), Action: "REJECT",
		TCPFlags: -1, TrafficPath: -1,
	}
	labels, _, line := (Encoder{Subcommand: "vpc"}).VPC(x)
	if _, ok := labels["vpc"]; ok {
		t.Errorf("empty vpc label set: %v", labels)
	}
	m := decode(t, line)
	if m["src_port"] != float64(0) || m["protocol"] != "icmp" {
		t.Errorf("icmp ports/protocol: %v", m)
	}
	for _, k := range []string{"tcp_flags", "traffic_path", "end_time", "pkt_src_addr", "vpc_id"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s should be omitted: %v", k, m[k])
		}
	}
}
