// Package s3rules derives security findings from an aggregated S3 server
// access log scan. Like the WAF rules, they need totals (how often one
// client was denied, how much one requester downloaded), so they run once
// over the merged summary.
package s3rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/findings"
	"github.com/gsmappdev/ctaudit/internal/stats"
)

const (
	defaultDeniedThreshold       = 100
	defaultDeleteThreshold       = 1000
	defaultEgressBytes     int64 = 10 << 30
	defaultMax                   = 500
	topShown                     = 3
)

// Options tunes the rules.
type Options struct {
	// DeniedThreshold is the denied request count at which one IP or
	// authenticated requester becomes a finding. Zero means 100.
	DeniedThreshold int
	// DeleteThreshold is the object delete count at which one principal
	// becomes a finding. Zero means 1000.
	DeleteThreshold int
	// EgressBytes is the bytes sent at which one IP or authenticated
	// requester becomes a finding. Zero means 10 GiB.
	EgressBytes int64
	// Max caps the findings returned; CRITICAL findings are always kept.
	// Zero means 500.
	Max int
}

func (o Options) withDefaults() Options {
	if o.DeniedThreshold <= 0 {
		o.DeniedThreshold = defaultDeniedThreshold
	}
	if o.DeleteThreshold <= 0 {
		o.DeleteThreshold = defaultDeleteThreshold
	}
	if o.EgressBytes <= 0 {
		o.EgressBytes = defaultEgressBytes
	}
	if o.Max <= 0 {
		o.Max = defaultMax
	}
	return o
}

type hit struct {
	f     findings.Finding
	count int
}

// top renders the largest entries of c as "key (n), key (n)".
func top(c stats.Counter) string {
	var parts []string
	for _, p := range c.TopN(topShown) {
		parts = append(parts, fmt.Sprintf("%s (%d)", p.Key, p.Count))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

func gib(n int64) string { return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30)) }

// Detect runs every rule over s. dropped counts findings removed by the cap.
func Detect(s *stats.S3Summary, o Options) ([]findings.Finding, int) {
	o = o.withDefaults()
	var hits []hit
	add := func(rule string, sev findings.Severity, title, actor, detail string, count int, at time.Time) {
		if at.IsZero() {
			at = s.First
		}
		hits = append(hits, hit{f: findings.Finding{Rule: rule, Severity: sev, Title: title, Actor: actor, Detail: detail, Time: at}, count: count})
	}

	for bucket, h := range s.AnonWrites {
		add("s3-anonymous-write", findings.SevCritical, "Anonymous write or delete succeeded", bucket,
			fmt.Sprintf("%d anonymous write or delete requests succeeded (%s) from %s; keys %s", h.Count, top(h.Ops), top(h.IPs), top(h.Keys)),
			h.Count, h.First)
	}
	for bucket, h := range s.AnonReads {
		add("s3-anonymous-read", findings.SevHigh, "Anonymous read succeeded", bucket,
			fmt.Sprintf("%d anonymous reads succeeded (%s) from %s; keys %s", h.Count, top(h.Ops), top(h.IPs), top(h.Keys)),
			h.Count, h.First)
	}
	for ip, n := range s.DeniedByIP {
		if ip != stats.S3Other && n >= o.DeniedThreshold {
			add("s3-access-denied-burst", findings.SevHigh, "Burst of denied requests", ip,
				fmt.Sprintf("%d denied requests (403 or AccessDenied) from this IP", n), n, time.Time{})
		}
	}
	for req, n := range s.DeniedByRequester {
		if req != stats.S3Other && n >= o.DeniedThreshold {
			add("s3-access-denied-burst", findings.SevHigh, "Burst of denied requests", req,
				fmt.Sprintf("%d denied requests (403 or AccessDenied) from this requester", n), n, time.Time{})
		}
	}
	for p, n := range s.DeletesByPrincipal {
		if p != stats.S3Other && n >= o.DeleteThreshold {
			add("s3-mass-delete", findings.SevHigh, "Mass object deletion", p,
				fmt.Sprintf("%d objects deleted", n), n, time.Time{})
		}
	}
	for _, c := range s.AccessChanges {
		target := c.Bucket
		if c.Key != "" {
			target += "/" + c.Key
		}
		add("s3-access-change", findings.SevMedium, "Bucket access configuration changed", c.Principal,
			fmt.Sprintf("%s on %s from %s", c.Operation, target, c.RemoteIP), 1, c.Time)
	}
	for req, n := range s.BytesByRequester {
		if req != stats.S3Other && int64(n) >= o.EgressBytes {
			add("s3-large-egress", findings.SevMedium, "Large data egress", req,
				fmt.Sprintf("%s sent to this requester", gib(int64(n))), n, time.Time{})
		}
	}
	for ip, n := range s.BytesByIP {
		if ip != stats.S3Other && int64(n) >= o.EgressBytes {
			add("s3-large-egress", findings.SevMedium, "Large data egress", ip,
				fmt.Sprintf("%s sent to this IP", gib(int64(n))), n, time.Time{})
		}
	}
	for _, r := range []struct {
		rule, title, what string
		c                 stats.Counter
	}{
		{"s3-weak-tls", "TLS below 1.2", "requests used TLS below 1.2", s.WeakTLSBy},
		{"s3-plain-http", "Requests over plain HTTP", "REST requests used plain HTTP", s.PlainHTTPBy},
		{"s3-sigv2", "Signature Version 2 requests", "requests were signed with Signature Version 2", s.SigV2By},
	} {
		for p, n := range r.c {
			if p != stats.S3Other {
				add(r.rule, findings.SevLow, r.title, p, fmt.Sprintf("%d %s", n, r.what), n, time.Time{})
			}
		}
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
		if a.f.Rule != b.f.Rule {
			return a.f.Rule < b.f.Rule
		}
		if !a.f.Time.Equal(b.f.Time) {
			return a.f.Time.Before(b.f.Time)
		}
		return a.f.Detail < b.f.Detail
	})

	out := make([]findings.Finding, 0, len(hits))
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
