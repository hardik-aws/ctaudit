package stats

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"
)

func TestCounterCapped(t *testing.T) {
	c := Counter{}
	for _, k := range []string{"a", "b", "c", "a", "d", ""} {
		c.addCapped(k, 1, 2)
	}
	c.addCapped("a", 0, 2)
	if want := (Counter{"a": 2, "b": 1, OtherKey: 2}); !reflect.DeepEqual(c, want) {
		t.Fatalf("after add: %v, want %v", c, want)
	}
	// Merging into a full counter: existing keys add, new keys fold into
	// (other), and the other side's (other) adds to ours.
	c.mergeCapped(Counter{"b": 3, "z": 4, OtherKey: 1}, 2)
	if want := (Counter{"a": 2, "b": 4, OtherKey: 7}); !reflect.DeepEqual(c, want) {
		t.Fatalf("after merge: %v, want %v", c, want)
	}
	// A non-positive max means DefaultMaxKeys.
	d := Counter{}
	d.addCapped("x", 5, 0)
	if d["x"] != 5 {
		t.Fatalf("default max: %v", d)
	}
}

func TestDistinctBounded(t *testing.T) {
	a1, a2, a3 := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("203.0.113.3")
	d := NewDistinct[uint16](3, 2)
	for _, p := range []uint16{22, 23, 22, 80, 443, 8080} {
		d.Add(a1, p)
	}
	d.Add(a2, 22)
	if d.Count(a1) != 3 || d.Count(a2) != 1 || d.Truncated {
		t.Fatalf("counts a1=%d a2=%d truncated=%v", d.Count(a1), d.Count(a2), d.Truncated)
	}
	got := d.Values(a1)
	slices.Sort(got)
	if !reflect.DeepEqual(got, []uint16{22, 23, 80}) {
		t.Fatalf("values = %v", got)
	}
	d.Add(a3, 1) // a third source past maxSources
	if !d.Truncated || d.Count(a3) != 0 || d.Sources() != 2 {
		t.Fatalf("maxSources not enforced: truncated=%v count=%d sources=%d", d.Truncated, d.Count(a3), d.Sources())
	}
	if got := d.AtLeast(3); !reflect.DeepEqual(got, []netip.Addr{a1}) {
		t.Fatalf("AtLeast(3) = %v", got)
	}
}

func TestDistinctMergeReachesThreshold(t *testing.T) {
	src := netip.MustParseAddr("198.51.100.9")
	// Two shards each saw two ports, one shared: the union has three.
	x, y := NewDistinct[uint16](3, 10), NewDistinct[uint16](3, 10)
	x.Add(src, 22)
	x.Add(src, 23)
	y.Add(src, 23)
	y.Add(src, 3389)
	x.Merge(y)
	x.Merge(nil)
	if x.Count(src) != 3 || len(x.AtLeast(3)) != 1 {
		t.Fatalf("merged count = %d", x.Count(src))
	}
	// Both shards already at the limit stay at the limit.
	p, q := NewDistinct[uint16](2, 10), NewDistinct[uint16](2, 10)
	p.Add(src, 1)
	p.Add(src, 2)
	q.Add(src, 3)
	q.Add(src, 4)
	p.Merge(q)
	if p.Count(src) != 2 {
		t.Fatalf("limit not kept on merge: %d", p.Count(src))
	}
	// Truncation propagates.
	r := NewDistinct[uint16](2, 1)
	r.Add(src, 1)
	r.Add(netip.MustParseAddr("198.51.100.10"), 1)
	s := NewDistinct[uint16](2, 1)
	s.Merge(r)
	if !s.Truncated {
		t.Fatal("Truncated not merged")
	}
}
