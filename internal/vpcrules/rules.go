// Package vpcrules derives network security findings from an aggregated VPC
// Flow Logs scan. Like the WAF rules they need totals (distinct ports per
// source, bytes per host), so they run once over the merged summary.
package vpcrules

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

// DefaultEgressBytes is the egress finding threshold: 1 GiB.
const DefaultEgressBytes int64 = 1 << 30

const (
	defaultMax  = 500
	samplePorts = 10
	topSources  = 5
)

// Options tunes the rules. Zero fields take the defaults.
type Options struct {
	// ScanPorts is the distinct rejected destination ports that make a
	// public source a port scanner. Zero means stats.DefaultScanPorts.
	ScanPorts int
	// SweepHosts is the distinct private destinations that make a source a
	// host sweep. Zero means stats.DefaultSweepHosts.
	SweepHosts int
	// EgressBytes is the bytes one private host must send to public
	// addresses to make a finding. Zero means DefaultEgressBytes.
	EgressBytes int64
	// Max caps the findings returned; CRITICAL findings are always kept.
	// Zero means 500.
	Max int
}

func (o Options) withDefaults() Options {
	if o.ScanPorts <= 0 {
		o.ScanPorts = stats.DefaultScanPorts
	}
	if o.SweepHosts <= 0 {
		o.SweepHosts = stats.DefaultSweepHosts
	}
	if o.EgressBytes <= 0 {
		o.EgressBytes = DefaultEgressBytes
	}
	if o.Max <= 0 {
		o.Max = defaultMax
	}
	return o
}

// Limits returns the summary limits that match these thresholds. Build the
// summary Detect will read with stats.NewVPCSummary(o.Limits()).
func (o Options) Limits() stats.VPCLimits {
	o = o.withDefaults()
	return stats.VPCLimits{ScanPorts: o.ScanPorts, SweepHosts: o.SweepHosts}
}

type hit struct {
	f     findings.Finding
	count int
}

// Detect runs every rule over s. dropped counts findings removed by the cap.
func Detect(s *stats.VPCSummary, o Options) ([]findings.Finding, int) {
	o = o.withDefaults()
	var hits []hit
	add := func(f findings.Finding, count int) {
		if f.Time.IsZero() {
			f.Time = s.First
		}
		hits = append(hits, hit{f: f, count: count})
	}

	for _, src := range s.ScanPorts.AtLeast(o.ScanPorts) {
		ports := s.ScanPorts.Values(src)
		slices.Sort(ports)
		sample := make([]string, 0, samplePorts)
		for _, p := range ports[:min(len(ports), samplePorts)] {
			sample = append(sample, strconv.Itoa(int(p)))
		}
		actor := src.String()
		add(findings.Finding{
			Rule: "vpc-port-scan", Severity: findings.SevHigh, Title: "Port scan from a public address", Actor: actor,
			Detail: fmt.Sprintf("rejected connection attempts to %d or more distinct ports (sample: %s); %d rejected flows",
				len(ports), strings.Join(sample, ", "), s.RejectsBySrc[actor]),
		}, len(ports))
	}

	for key, x := range s.Exposed {
		n, more := len(x.Sources), ""
		if _, ok := x.Sources[stats.OtherKey]; ok {
			n, more = n-1, "more than "
		}
		var top []string
		for _, p := range x.Sources.TopN(topSources + 1) {
			if p.Key != stats.OtherKey && len(top) < topSources {
				top = append(top, fmt.Sprintf("%s (%d)", p.Key, p.Count))
			}
		}
		add(findings.Finding{
			Rule: "vpc-sensitive-port-exposed", Severity: findings.SevHigh, Title: "Sensitive port reachable from the internet",
			Actor: key, Time: x.First,
			Detail: fmt.Sprintf("%d accepted flows, %s, from %s%d public sources; top: %s",
				x.Flows, formatBytes(x.Bytes), more, n, strings.Join(top, ", ")),
		}, x.Flows)
	}

	for _, src := range s.Sweep.AtLeast(o.SweepHosts) {
		n := s.Sweep.Count(src)
		add(findings.Finding{
			Rule: "vpc-host-sweep", Severity: findings.SevMedium, Title: "Host sweep", Actor: src.String(),
			Detail: fmt.Sprintf("started flows to %d or more distinct private addresses", n),
		}, n)
	}

	for host, b := range s.EgressBytes {
		if host == stats.OtherKey || int64(b) < o.EgressBytes {
			continue
		}
		add(findings.Finding{
			Rule: "vpc-large-egress", Severity: findings.SevMedium, Title: "Large egress to public addresses", Actor: host,
			Detail: fmt.Sprintf("sent %s in accepted flows it started to public addresses (threshold %s)",
				formatBytes(int64(b)), formatBytes(o.EgressBytes)),
		}, b)
	}

	for key, n := range s.Legacy {
		parts := strings.SplitN(key, "|", 3)
		if key == stats.OtherKey || len(parts) != 3 {
			continue
		}
		dir := "inbound from"
		if parts[1] == "out" {
			dir = "outbound to"
		}
		add(findings.Finding{
			Rule: "vpc-legacy-protocol", Severity: findings.SevLow, Title: "Legacy protocol in use", Actor: parts[0],
			Detail: fmt.Sprintf("%d accepted flows on %s %s public addresses", n, parts[2], dir),
		}, n)
	}

	sort.Slice(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if a.f.Severity != b.f.Severity {
			return a.f.Severity > b.f.Severity
		}
		if a.count != b.count {
			return a.count > b.count
		}
		if a.f.Actor != b.f.Actor {
			return a.f.Actor < b.f.Actor
		}
		return a.f.Rule < b.f.Rule
	})
	out := make([]findings.Finding, 0, min(len(hits), o.Max))
	dropped := 0
	for _, h := range hits {
		if len(out) >= o.Max && h.f.Severity != findings.SevCritical {
			dropped++
			continue
		}
		out = append(out, h.f)
	}
	return out, dropped
}

// MaxSeverity returns the highest severity in fs and whether fs is non-empty.
func MaxSeverity(fs []findings.Finding) (findings.Severity, bool) {
	if len(fs) == 0 {
		return findings.SevLow, false
	}
	max := fs[0].Severity
	for _, f := range fs[1:] {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max, true
}

// formatBytes renders a byte count with binary units, such as "1.0 GiB".
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
