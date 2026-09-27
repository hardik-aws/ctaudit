package flowlog

import "net/netip"

// privateNets are the ranges that never route on the internet: RFC 1918,
// carrier-grade NAT (RFC 6598), link-local, loopback, and their IPv6
// equivalents (unique local, link-local, loopback).
var privateNets = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

// IsPrivate reports whether a is inside a private range. IPv4-mapped IPv6
// addresses are judged by their IPv4 address.
func IsPrivate(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range privateNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsPublic reports whether a is a valid unicast address outside every
// private range. Unspecified and multicast addresses are neither private
// nor public.
func IsPublic(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !IsPrivate(a) && !a.IsUnspecified() && !a.IsMulticast()
}
