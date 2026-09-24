package elblog

import (
	"strings"
	"time"
)

// Filter selects access log entries. Every criterion is optional; an entry
// must satisfy all of the ones that are set.
type Filter struct {
	// ClientIP matches the client address as a substring, so "10.0." matches
	// a whole range.
	ClientIP string
	// Host matches the Host header (or TLS SNI when there is no Host) as a
	// case-insensitive substring.
	Host string
	// Path matches the request path, without query string, as a
	// case-insensitive substring.
	Path string
	// Target matches the target address as a substring.
	Target string
	// UserAgent matches the User-Agent as a case-insensitive substring.
	UserAgent string
	// Methods matches the HTTP method exactly, case-insensitively.
	Methods []string
	// Statuses matches the ELB status code. An entry like "4xx" or "5" matches
	// by prefix; "404" matches exactly.
	Statuses []string
	// SlowerThan keeps entries whose measurable latency is at least this long.
	SlowerThan time.Duration
	// Since and Until bound the entry time. Since is inclusive, Until
	// exclusive.
	Since time.Time
	Until time.Time
}

// Match reports whether the entry satisfies every criterion that is set.
func (f Filter) Match(e Entry) bool {
	if f.ClientIP != "" && !strings.Contains(e.ClientIP, f.ClientIP) {
		return false
	}
	if f.Host != "" && !containsFold(e.HostOrSNI(), f.Host) {
		return false
	}
	if f.Path != "" && !containsFold(e.Path, f.Path) {
		return false
	}
	if f.Target != "" && !strings.Contains(e.Target, f.Target) {
		return false
	}
	if f.UserAgent != "" && !containsFold(e.UserAgent, f.UserAgent) {
		return false
	}
	if len(f.Methods) > 0 && !anyEqualFold(f.Methods, e.Method) {
		return false
	}
	if len(f.Statuses) > 0 && !matchesStatus(f.Statuses, e.ELBStatus) {
		return false
	}
	if f.SlowerThan > 0 && (e.Latency < 0 || e.Latency < f.SlowerThan.Seconds()) {
		return false
	}
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.Time.Before(f.Until) {
		return false
	}
	return true
}

// MatchConn reports whether an ALB connection record satisfies the filter.
// Only the client IP and time bounds apply to connections, so a filter with
// any request-only criterion (host, path, target, user agent, method,
// status, or latency) matches no connections.
func (f Filter) MatchConn(e Entry) bool {
	if f.Host != "" || f.Path != "" || f.Target != "" || f.UserAgent != "" ||
		len(f.Methods) > 0 || len(f.Statuses) > 0 || f.SlowerThan > 0 {
		return false
	}
	if f.ClientIP != "" && !strings.Contains(e.ClientIP, f.ClientIP) {
		return false
	}
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.Time.Before(f.Until) {
		return false
	}
	return true
}

// IsNarrowing reports whether the filter is specific enough that listing the
// individual matching requests is useful. Time bounds do not count.
func (f Filter) IsNarrowing() bool {
	return f.ClientIP != "" || f.Host != "" || f.Path != "" || f.Target != "" ||
		f.UserAgent != "" || len(f.Methods) > 0 || len(f.Statuses) > 0 || f.SlowerThan > 0
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func anyEqualFold(candidates []string, value string) bool {
	for _, c := range candidates {
		if strings.EqualFold(c, value) {
			return true
		}
	}
	return false
}

func matchesStatus(patterns []string, status string) bool {
	if status == "" {
		return false
	}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		prefix := strings.TrimRight(p, "x")
		if prefix == "" {
			continue
		}
		if prefix != p || len(p) < 3 {
			if strings.HasPrefix(status, prefix) {
				return true
			}
		} else if status == p {
			return true
		}
	}
	return false
}
