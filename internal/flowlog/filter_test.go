package flowlog

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestFilterMatch(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	base := Entry{
		InterfaceID: "eni-0a1b", VPCID: "vpc-0123", SrcAddr: addr("203.0.113.9"), DstAddr: addr("10.0.1.10"),
		SrcPort: 40001, DstPort: 22, Protocol: 6, Start: t0, Action: "REJECT", LogStatus: StatusOK,
	}
	nat := base
	nat.SrcAddr, nat.PktSrcAddr = addr("10.0.0.200"), addr("10.0.1.5")

	cidrs := func(s ...string) []netip.Prefix {
		p, err := ParseCIDRs(s)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name string
		f    Filter
		e    Entry
		want bool
	}{
		{"empty", Filter{}, base, true},
		{"action fold", Filter{Actions: []string{"reject"}}, base, true},
		{"action other", Filter{Actions: []string{"ACCEPT"}}, base, false},
		{"src cidr", Filter{SrcCIDRs: cidrs("203.0.113.0/24")}, base, true},
		{"src single ip", Filter{SrcCIDRs: cidrs("203.0.113.8")}, base, false},
		{"src matches pkt-srcaddr", Filter{SrcCIDRs: cidrs("10.0.1.5")}, nat, true},
		{"src matches srcaddr beside pkt", Filter{SrcCIDRs: cidrs("10.0.0.200")}, nat, true},
		{"dst cidr", Filter{DstCIDRs: cidrs("10.0.0.0/16")}, base, true},
		{"dst cidr miss", Filter{DstCIDRs: cidrs("192.168.0.0/16")}, base, false},
		{"port dst", Filter{Ports: []PortRange{{22, 22}}}, base, true},
		{"port src range", Filter{Ports: []PortRange{{40000, 40010}}}, base, true},
		{"port miss", Filter{Ports: []PortRange{{80, 443}}}, base, false},
		{"protocol", Filter{Protocols: []int{17, 6}}, base, true},
		{"protocol miss", Filter{Protocols: []int{17}}, base, false},
		{"interface fold", Filter{Interfaces: []string{"ENI-0A1B"}}, base, true},
		{"vpc exact", Filter{VPCs: []string{"vpc-0123"}}, base, true},
		{"vpc miss", Filter{VPCs: []string{"vpc-9"}}, base, false},
		{"vpc case sensitive", Filter{VPCs: []string{"VPC-0123"}}, base, false},
		{"vpc absent from format", Filter{VPCs: []string{"vpc-0123"}}, Entry{Start: t0}, false},
		{"since inclusive", Filter{Since: t0}, base, true},
		{"until exclusive", Filter{Until: t0}, base, false},
		{"zero start outside window", Filter{Since: t0}, Entry{}, false},
	} {
		if got := tc.f.Match(tc.e); got != tc.want {
			t.Errorf("%s: Match = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFilterIsNarrowing(t *testing.T) {
	now := time.Now()
	if (Filter{Since: now, Until: now}).IsNarrowing() {
		t.Fatal("time-only filter is not narrowing")
	}
	for _, f := range []Filter{
		{Actions: []string{"REJECT"}}, {SrcCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		{DstCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, {Ports: []PortRange{{22, 22}}},
		{Protocols: []int{6}}, {Interfaces: []string{"eni-1"}}, {VPCs: []string{"vpc-1"}},
	} {
		if !f.IsNarrowing() {
			t.Errorf("%+v should be narrowing", f)
		}
	}
}

func TestParsers(t *testing.T) {
	p, err := ParseCIDRs([]string{"10.1.2.3/8", "203.0.113.9", "2001:db8::/32"})
	if err != nil || p[0] != netip.MustParsePrefix("10.0.0.0/8") || p[1] != netip.MustParsePrefix("203.0.113.9/32") || p[2].Bits() != 32 {
		t.Fatalf("ParseCIDRs = %v, %v", p, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "nope", ""} {
		if _, err := ParseCIDRs([]string{bad}); err == nil {
			t.Errorf("ParseCIDRs(%q) accepted", bad)
		}
	}
	ports, err := ParsePorts([]string{"22", "8000-8100"})
	if err != nil || !reflect.DeepEqual(ports, []PortRange{{22, 22}, {8000, 8100}}) {
		t.Fatalf("ParsePorts = %v, %v", ports, err)
	}
	for _, bad := range []string{"70000", "-1", "9-3", "a-b", "22-"} {
		if _, err := ParsePorts([]string{bad}); err == nil {
			t.Errorf("ParsePorts(%q) accepted", bad)
		}
	}
	protos, err := ParseProtocols([]string{"TCP", "udp", "icmpv6", "47"})
	if err != nil || !reflect.DeepEqual(protos, []int{6, 17, 58, 47}) {
		t.Fatalf("ParseProtocols = %v, %v", protos, err)
	}
	for _, bad := range []string{"quic", "256", "-3"} {
		if _, err := ParseProtocols([]string{bad}); err == nil {
			t.Errorf("ParseProtocols(%q) accepted", bad)
		}
	}
}
