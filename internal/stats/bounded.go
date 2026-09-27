package stats

import (
	"net/netip"
	"sort"
)

// DefaultMaxKeys caps every counter of a VPC summary. Flow logs can carry
// millions of distinct addresses and pairs; past the cap, new keys are
// counted under OtherKey so totals stay exact while memory stays bounded.
const DefaultMaxKeys = 50000

// OtherKey collects the counts of keys that arrived after a counter was full.
const OtherKey = "(other)"

// addCapped adds n to key. A key already present, or any key while the
// counter holds fewer than max keys, is added as is; otherwise n is added
// to OtherKey. The counter therefore holds at most max keys plus OtherKey.
// Empty keys and n == 0 are ignored. A non-positive max means
// DefaultMaxKeys.
func (c Counter) addCapped(key string, n, max int) {
	if key == "" || n == 0 {
		return
	}
	if max <= 0 {
		max = DefaultMaxKeys
	}
	if _, ok := c[key]; ok || len(c) < max {
		c[key] += n
		return
	}
	c[OtherKey] += n
}

// mergeCapped adds every entry of o with addCapped, so the cap survives
// shard merges.
func (c Counter) mergeCapped(o Counter, max int) {
	for k, v := range o {
		c.addCapped(k, v, max)
	}
}

// Distinct tracks, per source address, a bounded set of distinct values.
// Each source keeps at most limit values and at most maxSources sources are
// tracked. The threshold rules only ask whether a source reached limit
// distinct values, so a set capped at limit answers exactly, and the union
// of two capped sets answers exactly too. New sources past maxSources are
// dropped and Truncated is set.
type Distinct[K comparable] struct {
	limit      int
	maxSources int
	sets       map[netip.Addr]map[K]struct{}
	// Truncated reports that a source was dropped because maxSources
	// sources were already tracked.
	Truncated bool
}

// NewDistinct returns an empty tracker. Non-positive arguments mean 1.
func NewDistinct[K comparable](limit, maxSources int) *Distinct[K] {
	return &Distinct[K]{limit: max(limit, 1), maxSources: max(maxSources, 1), sets: map[netip.Addr]map[K]struct{}{}}
}

// Add records that src was seen with v.
func (d *Distinct[K]) Add(src netip.Addr, v K) {
	set, ok := d.sets[src]
	if !ok {
		if len(d.sets) >= d.maxSources {
			d.Truncated = true
			return
		}
		set = map[K]struct{}{}
		d.sets[src] = set
	}
	if len(set) < d.limit {
		set[v] = struct{}{}
	}
}

// Merge adds every value of o. A nil o is a no-op.
func (d *Distinct[K]) Merge(o *Distinct[K]) {
	if o == nil {
		return
	}
	d.Truncated = d.Truncated || o.Truncated
	for src, set := range o.sets {
		for v := range set {
			d.Add(src, v)
		}
	}
}

// Count returns how many distinct values src has, at most the limit.
func (d *Distinct[K]) Count(src netip.Addr) int { return len(d.sets[src]) }

// Sources returns how many sources are tracked.
func (d *Distinct[K]) Sources() int { return len(d.sets) }

// AtLeast returns, sorted, every source with at least n distinct values.
func (d *Distinct[K]) AtLeast(n int) []netip.Addr {
	var out []netip.Addr
	for src, set := range d.sets {
		if len(set) >= n {
			out = append(out, src)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// Values returns src's values in no particular order.
func (d *Distinct[K]) Values(src netip.Addr) []K {
	out := make([]K, 0, len(d.sets[src]))
	for v := range d.sets[src] {
		out = append(out, v)
	}
	return out
}
