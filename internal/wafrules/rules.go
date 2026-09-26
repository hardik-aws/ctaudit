// Package wafrules derives security findings from an aggregated WAF scan.
// Unlike CloudTrail rules, which judge one record at a time, these rules
// need totals (how often an IP was blocked, whether it was also allowed),
// so they run once over the merged summary.
package wafrules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

const (
	defaultBlockThreshold = 100
	defaultMax            = 500
	rateTopIPs            = 5
)

// Options tunes the rules.
type Options struct {
	// BlockThreshold is the block count at which a client IP becomes a
	// finding. Zero means 100.
	BlockThreshold int
	// Max caps the findings returned; CRITICAL findings are always kept.
	// Zero means 500.
	Max int
}

type hit struct {
	f     findings.Finding
	count int
}

// Detect runs every rule over s. dropped counts findings removed by the cap.
func Detect(s *stats.WAFSummary, o Options) ([]findings.Finding, int) {
	threshold := o.BlockThreshold
	if threshold <= 0 {
		threshold = defaultBlockThreshold
	}
	max := o.Max
	if max <= 0 {
		max = defaultMax
	}
	challengeMin := threshold / 10
	if challengeMin < 1 {
		challengeMin = 1
	}

	var hits []hit
	add := func(rule string, sev findings.Severity, title, actor, detail string, count int, at func() findings.Finding) {
		f := findings.Finding{Rule: rule, Severity: sev, Title: title, Actor: actor, Detail: detail, Time: s.First}
		if at != nil {
			f.Time = at().Time
		}
		hits = append(hits, hit{f: f, count: count})
	}

	for ip, h := range s.Exploits {
		first := h.First
		var ms []string
		for _, p := range h.Matches.TopN(3) {
			ms = append(ms, p.Key)
		}
		add("waf-exploit-allowed", findings.SevCritical, "Exploit payload allowed", ip,
			fmt.Sprintf("%d allowed requests matched COUNT-mode exploit rules (%s); first at %s", h.Count, strings.Join(ms, ", "), h.URI),
			h.Count, func() findings.Finding { return findings.Finding{Time: first} })
	}
	for ip, st := range s.IPs {
		switch {
		case st.Blocks >= threshold && st.Allows > 0:
			add("waf-attacker-allowed", findings.SevHigh, "Blocked client also allowed", ip,
				fmt.Sprintf("%d blocked and %d allowed requests", st.Blocks, st.Allows), st.Blocks, nil)
		case st.Blocks >= threshold:
			add("waf-persistent-blocked-ip", findings.SevMedium, "Persistent blocked client", ip,
				fmt.Sprintf("%d blocked requests", st.Blocks), st.Blocks, nil)
		}
		if st.ChallengeFails >= challengeMin {
			add("waf-challenge-failures", findings.SevLow, "Repeated CAPTCHA or challenge failures", ip,
				fmt.Sprintf("%d failed CAPTCHA or challenge responses", st.ChallengeFails), st.ChallengeFails, nil)
		}
	}
	for rule, ips := range s.RateByRule {
		total := 0
		for _, n := range ips {
			total += n
		}
		var top []string
		for _, p := range ips.TopN(rateTopIPs) {
			top = append(top, fmt.Sprintf("%s (%d)", p.Key, p.Count))
		}
		add("waf-rate-limited", findings.SevHigh, "Rate limit triggered", rule,
			fmt.Sprintf("%d requests limited; top clients: %s", total, strings.Join(top, ", ")), total, nil)
	}
	for rule, n := range s.ByCountRule {
		add("waf-count-rule", findings.SevMedium, "COUNT rule would block", rule,
			fmt.Sprintf("%d requests matched this rule in COUNT mode", n), n, nil)
	}
	if s.Oversize > 0 {
		add("waf-oversize", findings.SevMedium, "Request fields over the inspection limit", "",
			fmt.Sprintf("%d requests had a body, headers, or cookies larger than WAF inspects", s.Oversize), s.Oversize, nil)
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

	out := make([]findings.Finding, 0, len(hits))
	dropped := 0
	for _, h := range hits {
		if len(out) >= max && h.f.Severity != findings.SevCritical {
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
