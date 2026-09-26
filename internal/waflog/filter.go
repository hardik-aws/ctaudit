package waflog

import (
	"strings"
	"time"
)

// Filter selects WAF log entries. Every criterion is optional; an entry
// must satisfy all of the ones that are set.
type Filter struct {
	// Actions matches the action exactly, case-insensitively.
	Actions []string
	// ClientIP matches the client address as a substring, so "10.0."
	// matches a whole range.
	ClientIP string
	// Countries matches the two-letter country code, case-insensitively.
	Countries []string
	// Rule, URI, and Host match as case-insensitive substrings.
	Rule string
	URI  string
	Host string
	// Since is inclusive, Until exclusive.
	Since time.Time
	Until time.Time
}

// Match reports whether the entry satisfies every criterion that is set.
func (f Filter) Match(e Entry) bool {
	if len(f.Actions) > 0 && !anyEqualFold(f.Actions, e.Action) {
		return false
	}
	if f.ClientIP != "" && !strings.Contains(e.ClientIP, f.ClientIP) {
		return false
	}
	if len(f.Countries) > 0 && !anyEqualFold(f.Countries, e.Country) {
		return false
	}
	if f.Rule != "" && !containsFold(e.Rule, f.Rule) {
		return false
	}
	if f.URI != "" && !containsFold(e.URI, f.URI) {
		return false
	}
	if f.Host != "" && !containsFold(e.Host, f.Host) {
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

// IsNarrowing reports whether listing the individual matching requests is
// useful. Time bounds do not count.
func (f Filter) IsNarrowing() bool {
	return len(f.Actions) > 0 || f.ClientIP != "" || len(f.Countries) > 0 || f.Rule != "" || f.URI != "" || f.Host != ""
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func anyEqualFold(candidates []string, value string) bool {
	for _, c := range candidates {
		if strings.EqualFold(strings.TrimSpace(c), value) {
			return true
		}
	}
	return false
}
