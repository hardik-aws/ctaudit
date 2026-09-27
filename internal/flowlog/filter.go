package flowlog

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// PortRange is an inclusive port range; a single port has Lo == Hi.
type PortRange struct{ Lo, Hi int }

// Filter selects flow log entries. Every criterion is optional; an entry
// must satisfy all of the ones that are set, and any one value within a
// criterion.
type Filter struct {
	// Actions matches ACCEPT or REJECT, case-insensitively.
	Actions []string
	// SrcCIDRs matches when srcaddr or pkt-srcaddr is inside any prefix;
	// DstCIDRs does the same for the destination.
	SrcCIDRs []netip.Prefix
	DstCIDRs []netip.Prefix
	// Ports matches when either the source or the destination port is in
	// any range, so both directions of a conversation match.
	Ports []PortRange
	// Protocols matches IANA protocol numbers.
	Protocols []int
	// Interfaces match ENI IDs exactly, case-insensitively. VPCs match VPC IDs
	// exactly. A format without vpc-id never matches VPCs.
	Interfaces []string
	VPCs       []string
	// Since is inclusive, Until exclusive; both apply to Start.
	Since time.Time
	Until time.Time
}

// InWindow reports whether the entry's start falls in the window. An entry
// with no start is outside any bounded window.
func (f Filter) InWindow(e Entry) bool {
	if !f.Since.IsZero() && e.Start.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.Start.Before(f.Until) {
		return false
	}
	return true
}

// Match reports whether the entry satisfies every criterion that is set.
func (f Filter) Match(e Entry) bool {
	if !f.InWindow(e) {
		return false
	}
	if len(f.Actions) > 0 && !anyEqualFold(f.Actions, e.Action) {
		return false
	}
	if len(f.SrcCIDRs) > 0 && !inAny(f.SrcCIDRs, e.SrcAddr) && !inAny(f.SrcCIDRs, e.PktSrcAddr) {
		return false
	}
	if len(f.DstCIDRs) > 0 && !inAny(f.DstCIDRs, e.DstAddr) && !inAny(f.DstCIDRs, e.PktDstAddr) {
		return false
	}
	if len(f.Ports) > 0 && !portIn(f.Ports, e.SrcPort) && !portIn(f.Ports, e.DstPort) {
		return false
	}
	if len(f.Protocols) > 0 && !slices.Contains(f.Protocols, e.Protocol) {
		return false
	}
	if len(f.Interfaces) > 0 && !anyEqualFold(f.Interfaces, e.InterfaceID) {
		return false
	}
	if len(f.VPCs) > 0 && !slices.Contains(f.VPCs, e.VPCID) {
		return false
	}
	return true
}

// IsNarrowing reports whether listing the individual matching flows is
// useful. Time bounds do not count.
func (f Filter) IsNarrowing() bool {
	return len(f.Actions) > 0 || len(f.SrcCIDRs) > 0 || len(f.DstCIDRs) > 0 || len(f.Ports) > 0 ||
		len(f.Protocols) > 0 || len(f.Interfaces) > 0 || len(f.VPCs) > 0
}

func inAny(ps []netip.Prefix, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func portIn(rs []PortRange, p int) bool {
	if p < 0 {
		return false
	}
	for _, r := range rs {
		if p >= r.Lo && p <= r.Hi {
			return true
		}
	}
	return false
}

func anyEqualFold(candidates []string, value string) bool {
	if value == "" {
		return false
	}
	for _, c := range candidates {
		if strings.EqualFold(strings.TrimSpace(c), value) {
			return true
		}
	}
	return false
}

// ParseCIDRs parses CIDRs and bare addresses (a single-address prefix).
// Host bits are cleared, so 10.1.2.3/8 means 10.0.0.0/8.
func ParseCIDRs(items []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if strings.Contains(it, "/") {
			p, err := netip.ParsePrefix(it)
			if err != nil {
				return nil, fmt.Errorf("%q is not an IP address or CIDR", it)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(it)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR", it)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// ParsePorts parses ports ("22") and inclusive ranges ("8000-8100").
func ParsePorts(items []string) ([]PortRange, error) {
	out := make([]PortRange, 0, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		lo, hi, isRange := strings.Cut(it, "-")
		if !isRange {
			hi = lo
		}
		l, err1 := strconv.Atoi(lo)
		h, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || l < 0 || h > 65535 || l > h {
			return nil, fmt.Errorf("%q is not a port (0-65535) or a range such as 8000-8100", it)
		}
		out = append(out, PortRange{l, h})
	}
	return out, nil
}

// ParseProtocols parses protocol names (tcp, udp, icmp, icmpv6, gre, esp,
// ah, sctp; case-insensitive) and numbers 0 to 255.
func ParseProtocols(items []string) ([]int, error) {
	out := make([]int, 0, len(items))
	for _, it := range items {
		it = strings.ToLower(strings.TrimSpace(it))
		found := -1
		for n, name := range protocolNames {
			if name == it {
				found = n
			}
		}
		if found < 0 {
			n, err := strconv.Atoi(it)
			if err != nil || n < 0 || n > 255 {
				return nil, fmt.Errorf("%q is not a protocol name (tcp, udp, icmp, icmpv6, gre, esp, ah, sctp) or number 0-255", it)
			}
			found = n
		}
		out = append(out, found)
	}
	return out, nil
}
