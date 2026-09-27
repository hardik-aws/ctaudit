package flowlog

import (
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	for _, s := range []string{"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1",
		"100.127.255.255", "169.254.169.254", "127.0.0.1", "fd00::1", "fe80::1", "::1", "::ffff:10.0.0.1"} {
		a := netip.MustParseAddr(s)
		if !IsPrivate(a) || IsPublic(a) {
			t.Errorf("%s: private %v public %v, want private", s, IsPrivate(a), IsPublic(a))
		}
	}
	for _, s := range []string{"8.8.8.8", "172.32.0.1", "100.128.0.1", "203.0.113.9", "2001:db8::1", "2600::1", "::ffff:8.8.8.8"} {
		a := netip.MustParseAddr(s)
		if IsPrivate(a) || !IsPublic(a) {
			t.Errorf("%s: private %v public %v, want public", s, IsPrivate(a), IsPublic(a))
		}
	}
	for _, a := range []netip.Addr{{}, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("224.0.0.1"), netip.MustParseAddr("ff02::1")} {
		if IsPrivate(a) || IsPublic(a) {
			t.Errorf("%v: private %v public %v, want neither", a, IsPrivate(a), IsPublic(a))
		}
	}
}
