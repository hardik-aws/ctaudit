package stats

import (
	"net/netip"
	"slices"
	"time"

	"github.com/gsmappdev/ctaudit/internal/flowlog"
)

// VPCSensitivePorts are the destination ports whose exposure to public
// sources is a finding: SSH, RDP, MySQL, PostgreSQL, SQL Server, Redis,
// Elasticsearch, MongoDB, the Docker API, and memcached.
var VPCSensitivePorts = []int{22, 3389, 3306, 5432, 1433, 6379, 9200, 27017, 2375, 11211}

// VPCLegacyPorts are FTP, Telnet, and SMB.
var VPCLegacyPorts = []int{21, 23, 445}

const (
	// DefaultMaxSources caps the sources each distinct tracker follows.
	DefaultMaxSources = 20000
	// DefaultScanPorts and DefaultSweepHosts are the rule thresholds, which
	// are also the per-source limits of the distinct trackers.
	DefaultScanPorts  = 25
	DefaultSweepHosts = 50
	// ExposedSourceCap caps the source counter of each exposed service.
	ExposedSourceCap = 1000
)

// VPCLimits bounds a VPCSummary's memory. Zero fields take the defaults.
type VPCLimits struct {
	MaxKeys    int
	MaxSources int
	ScanPorts  int
	SweepHosts int
}

func (l VPCLimits) withDefaults() VPCLimits {
	if l.MaxKeys <= 0 {
		l.MaxKeys = DefaultMaxKeys
	}
	if l.MaxSources <= 0 {
		l.MaxSources = DefaultMaxSources
	}
	if l.ScanPorts <= 0 {
		l.ScanPorts = DefaultScanPorts
	}
	if l.SweepHosts <= 0 {
		l.SweepHosts = DefaultSweepHosts
	}
	return l
}

// ExposedService aggregates accepted flows from public sources that look
// like they started the conversation (see initiator) to one private host,
// port, and protocol.
type ExposedService struct {
	Flows int
	Bytes int64
	First time.Time
	// Sources counts flows per public source, capped at ExposedSourceCap
	// keys plus OtherKey.
	Sources Counter
}

// VPCSummary aggregates flow log records. Like the other summaries it is
// owned by one goroutine during a scan and combined with Merge afterwards.
// Every counter is capped at Limits.MaxKeys keys plus OtherKey.
type VPCSummary struct {
	Limits VPCLimits

	Flows       int
	Bytes       int64
	Packets     int64
	First, Last time.Time
	// NoData and SkipData count the status rows inside the window: an
	// interface with no traffic, and records skipped during capture.
	NoData   int
	SkipData int

	ByAction      Counter
	BytesByAction Counter
	ByProtocol    Counter
	// ByDstPort is keyed by flowlog.Entry.Service, such as "443/tcp".
	ByDstPort    Counter
	ByInterface  Counter
	ByDirection  Counter
	BySrc        Counter
	ByDst        Counter
	PairBytes    Counter // "src -> dst" to bytes
	RejectsBySrc Counter

	// ByHour is keyed by Unix hour of the flow start; values count actions.
	ByHour map[int64]Counter

	ScanPorts *Distinct[uint16]
	Sweep     *Distinct[netip.Addr]

	// Exposed is keyed "10.0.1.20:22/tcp" (IPv6 as "[fd00::5]:5432/tcp"). It
	// only holds flows whose public source looks like it started the flow.
	Exposed map[string]*ExposedService
	// ExposedDropped counts flows for exposed services past the key cap.
	ExposedDropped int

	// EgressBytes is bytes per private source to public destinations.
	EgressBytes Counter
	// Legacy is keyed "<private>|in|23/tcp" or "<private>|out|445/tcp".
	Legacy Counter
}

// NewVPCSummary returns an empty summary bounded by l.
func NewVPCSummary(l VPCLimits) *VPCSummary {
	l = l.withDefaults()
	return &VPCSummary{
		Limits:        l,
		ByAction:      Counter{},
		BytesByAction: Counter{},
		ByProtocol:    Counter{},
		ByDstPort:     Counter{},
		ByInterface:   Counter{},
		ByDirection:   Counter{},
		BySrc:         Counter{},
		ByDst:         Counter{},
		PairBytes:     Counter{},
		RejectsBySrc:  Counter{},
		ByHour:        map[int64]Counter{},
		ScanPorts:     NewDistinct[uint16](l.ScanPorts, l.MaxSources),
		Sweep:         NewDistinct[netip.Addr](l.SweepHosts, l.MaxSources),
		Exposed:       map[string]*ExposedService{},
		EgressBytes:   Counter{},
		Legacy:        Counter{},
	}
}

// AddStatus counts a NODATA or SKIPDATA row. Other statuses are ignored.
func (s *VPCSummary) AddStatus(status string) {
	switch status {
	case flowlog.StatusNoData:
		s.NoData++
	case flowlog.StatusSkipData:
		s.SkipData++
	}
}

func addrKey(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// initiator reports whether the flow's source looks like the side that
// opened the conversation: ICMP, either port unknown, or a source port above
// the destination port (clients use high ephemeral ports).
func initiator(e flowlog.Entry) bool {
	if e.Protocol == 1 || e.Protocol == 58 || e.SrcPort < 0 || e.DstPort < 0 {
		return true
	}
	return e.SrcPort > e.DstPort
}

// connAttempt reports whether a flow may be a connection attempt: not TCP,
// TCP with unknown flags, or TCP flags that are SYN without ACK. Rejected
// TCP flows without SYN, and a SYN-ACK reply (the answer to a SYN sent the
// other way), are return traffic, not probes.
func connAttempt(e flowlog.Entry) bool {
	return e.Protocol != 6 || e.TCPFlags < 0 || e.TCPFlags&0x12 == 0x02
}

func (s *VPCSummary) exposed(key string) *ExposedService {
	if x, ok := s.Exposed[key]; ok {
		return x
	}
	if len(s.Exposed) >= s.Limits.MaxKeys {
		return nil
	}
	x := &ExposedService{Sources: Counter{}}
	s.Exposed[key] = x
	return x
}

// Add folds one flow (a record with log-status OK) into the summary.
func (s *VPCSummary) Add(e flowlog.Entry) {
	m := s.Limits.MaxKeys
	s.Flows++
	s.Bytes += e.Bytes
	s.Packets += e.Packets
	if !e.Start.IsZero() {
		if s.First.IsZero() || e.Start.Before(s.First) {
			s.First = e.Start
		}
		if s.Last.IsZero() || e.Start.After(s.Last) {
			s.Last = e.Start
		}
		h := e.Start.Unix() / 3600
		if s.ByHour[h] == nil {
			s.ByHour[h] = Counter{}
		}
		s.ByHour[h].addCapped(e.Action, 1, m)
	}
	s.ByAction.addCapped(e.Action, 1, m)
	s.BytesByAction.addCapped(e.Action, int(e.Bytes), m)
	s.ByProtocol.addCapped(e.ProtocolName(), 1, m)
	s.ByDstPort.addCapped(e.Service(), 1, m)
	s.ByInterface.addCapped(e.InterfaceID, 1, m)
	s.ByDirection.addCapped(e.FlowDirection, 1, m)

	src, dst := e.Source().Unmap(), e.Dest().Unmap()
	sk, dk := addrKey(src), addrKey(dst)
	s.BySrc.addCapped(sk, 1, m)
	s.ByDst.addCapped(dk, 1, m)
	if sk != "" && dk != "" {
		s.PairBytes.addCapped(sk+" -> "+dk, int(e.Bytes), m)
	}

	accept, reject := e.Action == "ACCEPT", e.Action == "REJECT"
	tcpUDP := e.Protocol == 6 || e.Protocol == 17
	srcPublic, srcPrivate := flowlog.IsPublic(src), flowlog.IsPrivate(src)
	dstPublic, dstPrivate := flowlog.IsPublic(dst), flowlog.IsPrivate(dst)
	started := initiator(e)

	if reject {
		s.RejectsBySrc.addCapped(sk, 1, m)
		if srcPublic && tcpUDP && e.DstPort >= 0 && connAttempt(e) {
			s.ScanPorts.Add(src, uint16(e.DstPort))
		}
	}
	if src.IsValid() && dstPrivate && started {
		s.Sweep.Add(src, dst)
	}
	if !accept {
		return
	}
	if srcPublic && dstPrivate && tcpUDP && started && e.FlowDirection != "egress" && slices.Contains(VPCSensitivePorts, e.DstPort) {
		key := netip.AddrPortFrom(dst, uint16(e.DstPort)).String() + "/" + e.ProtocolName()
		if x := s.exposed(key); x != nil {
			x.Flows++
			x.Bytes += e.Bytes
			if x.First.IsZero() || (!e.Start.IsZero() && e.Start.Before(x.First)) {
				x.First = e.Start
			}
			x.Sources.addCapped(sk, 1, ExposedSourceCap)
		} else {
			s.ExposedDropped++
		}
	}
	if srcPrivate && dstPublic && started {
		s.EgressBytes.addCapped(sk, int(e.Bytes), m)
	}
	if tcpUDP && slices.Contains(VPCLegacyPorts, e.DstPort) {
		switch {
		case srcPublic && dstPrivate:
			s.Legacy.addCapped(dk+"|in|"+e.Service(), 1, m)
		case srcPrivate && dstPublic:
			s.Legacy.addCapped(sk+"|out|"+e.Service(), 1, m)
		}
	}
}

// Merge adds o into s, keeping s's caps.
func (s *VPCSummary) Merge(o *VPCSummary) {
	m := s.Limits.MaxKeys
	s.Flows += o.Flows
	s.Bytes += o.Bytes
	s.Packets += o.Packets
	s.NoData += o.NoData
	s.SkipData += o.SkipData
	if !o.First.IsZero() && (s.First.IsZero() || o.First.Before(s.First)) {
		s.First = o.First
	}
	if o.Last.After(s.Last) {
		s.Last = o.Last
	}
	for h, c := range o.ByHour {
		if s.ByHour[h] == nil {
			s.ByHour[h] = Counter{}
		}
		s.ByHour[h].mergeCapped(c, m)
	}
	for _, p := range []struct{ dst, src Counter }{
		{s.ByAction, o.ByAction}, {s.BytesByAction, o.BytesByAction}, {s.ByProtocol, o.ByProtocol},
		{s.ByDstPort, o.ByDstPort}, {s.ByInterface, o.ByInterface}, {s.ByDirection, o.ByDirection},
		{s.BySrc, o.BySrc}, {s.ByDst, o.ByDst}, {s.PairBytes, o.PairBytes}, {s.RejectsBySrc, o.RejectsBySrc},
		{s.EgressBytes, o.EgressBytes}, {s.Legacy, o.Legacy},
	} {
		p.dst.mergeCapped(p.src, m)
	}
	for k, x := range o.Exposed {
		y := s.exposed(k)
		if y == nil {
			s.ExposedDropped += x.Flows
			continue
		}
		y.Flows += x.Flows
		y.Bytes += x.Bytes
		if !x.First.IsZero() && (y.First.IsZero() || x.First.Before(y.First)) {
			y.First = x.First
		}
		y.Sources.mergeCapped(x.Sources, ExposedSourceCap)
	}
	s.ExposedDropped += o.ExposedDropped
	s.ScanPorts.Merge(o.ScanPorts)
	s.Sweep.Merge(o.Sweep)
}

// Accepted returns the ACCEPT flow count.
func (s *VPCSummary) Accepted() int { return s.ByAction["ACCEPT"] }

// Rejected returns the REJECT flow count.
func (s *VPCSummary) Rejected() int { return s.ByAction["REJECT"] }

// RejectRate returns rejected flows as a fraction of all flows.
func (s *VPCSummary) RejectRate() float64 {
	if s.Flows == 0 {
		return 0
	}
	return float64(s.Rejected()) / float64(s.Flows)
}

// Truncated reports that a bounded structure dropped data, so findings may
// be incomplete. Counters folding into OtherKey do not count: their totals
// stay exact.
func (s *VPCSummary) Truncated() bool {
	return s.ScanPorts.Truncated || s.Sweep.Truncated || s.ExposedDropped > 0
}
