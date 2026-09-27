package sink

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/gsmappdev/ctaudit/internal/flowlog"
)

// flowLine is one VPC flow. Unknown numeric fields are omitted rather than
// written as -1; ports stay, because 0 is a real ICMP value. source and
// destination are the effective endpoints (pkt-* address when present), so
// dashboards need not coalesce the two address pairs.
type flowLine struct {
	Kind             string    `json:"kind"`
	RunID            string    `json:"run_id"`
	EventTime        time.Time `json:"event_time"`
	EndTime          time.Time `json:"end_time,omitzero"`
	Action           string    `json:"action,omitempty"`
	LogStatus        string    `json:"log_status,omitempty"`
	Version          *int      `json:"version,omitempty"`
	AccountID        string    `json:"account_id,omitempty"`
	InterfaceID      string    `json:"interface_id,omitempty"`
	VPCID            string    `json:"vpc_id,omitempty"`
	SubnetID         string    `json:"subnet_id,omitempty"`
	InstanceID       string    `json:"instance_id,omitempty"`
	Source           string    `json:"source,omitempty"`
	Destination      string    `json:"destination,omitempty"`
	SrcAddr          string    `json:"src_addr,omitempty"`
	DstAddr          string    `json:"dst_addr,omitempty"`
	SrcPort          *int      `json:"src_port,omitempty"`
	DstPort          *int      `json:"dst_port,omitempty"`
	Protocol         string    `json:"protocol,omitempty"`
	Packets          int64     `json:"packets"`
	Bytes            int64     `json:"bytes"`
	TCPFlags         *int      `json:"tcp_flags,omitempty"`
	Type             string    `json:"type,omitempty"`
	PktSrcAddr       string    `json:"pkt_src_addr,omitempty"`
	PktDstAddr       string    `json:"pkt_dst_addr,omitempty"`
	Region           string    `json:"region,omitempty"`
	AZID             string    `json:"az_id,omitempty"`
	PktSrcAWSService string    `json:"pkt_src_aws_service,omitempty"`
	PktDstAWSService string    `json:"pkt_dst_aws_service,omitempty"`
	FlowDirection    string    `json:"flow_direction,omitempty"`
	TrafficPath      *int      `json:"traffic_path,omitempty"`
	RejectReason     string    `json:"reject_reason,omitempty"`
}

// optInt maps the decoder's -1 (unknown) to an omitted field.
func optInt(n int) *int {
	if n < 0 {
		return nil
	}
	return &n
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// VPC encodes one flow log record, stored at the flow's start time.
func (e Encoder) VPC(x flowlog.Entry) (Labels, time.Time, []byte) {
	labels := e.labels("flow", "action", x.Action, "vpc", x.VPCID)
	b, _ := json.Marshal(flowLine{
		Kind: "flow", RunID: e.RunID, EventTime: x.Start, EndTime: x.End, Action: x.Action, LogStatus: x.LogStatus,
		Version: optInt(x.Version), AccountID: x.AccountID, InterfaceID: x.InterfaceID, VPCID: x.VPCID,
		SubnetID: x.SubnetID, InstanceID: x.InstanceID, Source: addrString(x.Source()), Destination: addrString(x.Dest()),
		SrcAddr: addrString(x.SrcAddr), DstAddr: addrString(x.DstAddr), SrcPort: optInt(x.SrcPort), DstPort: optInt(x.DstPort),
		Protocol: x.ProtocolName(), Packets: x.Packets, Bytes: x.Bytes, TCPFlags: optInt(x.TCPFlags), Type: x.Type,
		PktSrcAddr: addrString(x.PktSrcAddr), PktDstAddr: addrString(x.PktDstAddr), Region: x.Region, AZID: x.AZID,
		PktSrcAWSService: x.PktSrcAWSService, PktDstAWSService: x.PktDstAWSService, FlowDirection: x.FlowDirection,
		TrafficPath: optInt(x.TrafficPath), RejectReason: x.RejectReason,
	})
	return labels, x.Start, b
}
