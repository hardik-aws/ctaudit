// Package query filters CloudTrail records. Every criterion is optional; a
// record must satisfy all of the ones that are set.
package query

import (
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
)

// Filter selects records for inclusion in the report.
type Filter struct {
	// Principal matches the record's actor as a case-insensitive substring,
	// so "alice" finds "arn:aws:iam::111122223333:user/alice".
	Principal string
	// Resource matches any resource ARN, or the raw request parameters, as a
	// case-insensitive substring.
	Resource string
	// SourceIP matches sourceIPAddress as a case-insensitive substring.
	SourceIP string
	// Events matches eventName exactly, case-insensitively. Any entry matches.
	Events []string
	// Sources matches eventSource exactly, case-insensitively, with or
	// without the ".amazonaws.com" suffix. Any entry matches.
	Sources []string
	// ErrorsOnly keeps only records that carry an errorCode.
	ErrorsOnly bool
	// WritesOnly keeps only mutating calls.
	WritesOnly bool
	// Since and Until bound eventTime. Since is inclusive, Until exclusive.
	Since time.Time
	Until time.Time
}

// Match reports whether the record satisfies every criterion that is set.
func (f Filter) Match(r ctevent.Record) bool {
	if f.Principal != "" && !containsFold(r.Actor(), f.Principal) {
		return false
	}
	if f.Resource != "" && !matchesResource(r, f.Resource) {
		return false
	}
	if f.SourceIP != "" && !containsFold(r.SourceIPAddress, f.SourceIP) {
		return false
	}
	if len(f.Events) > 0 && !anyEqualFold(f.Events, r.EventName) {
		return false
	}
	if len(f.Sources) > 0 && !matchesSource(r, f.Sources) {
		return false
	}
	if f.ErrorsOnly && r.ErrorCode == "" {
		return false
	}
	if f.WritesOnly && !r.IsWrite() {
		return false
	}
	if !f.Since.IsZero() && r.EventTime.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !r.EventTime.Before(f.Until) {
		return false
	}
	return true
}

// IsNarrowing reports whether the filter is specific enough that listing the
// individual matching events is useful. Time bounds and WritesOnly do not
// count, because they still admit millions of records.
func (f Filter) IsNarrowing() bool {
	return f.Principal != "" || f.Resource != "" || f.SourceIP != "" ||
		len(f.Events) > 0 || f.ErrorsOnly
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

func matchesSource(r ctevent.Record, sources []string) bool {
	for _, s := range sources {
		short := strings.TrimSuffix(s, ".amazonaws.com")
		if strings.EqualFold(short, r.ServiceName()) {
			return true
		}
	}
	return false
}

func matchesResource(r ctevent.Record, needle string) bool {
	for _, res := range r.Resources {
		if containsFold(res.ARN, needle) {
			return true
		}
	}
	// Fall back to the raw request parameters: plenty of events identify the
	// resource only there (e.g. S3 bucketName, EC2 instanceId).
	return containsFold(string(r.RequestParameters), needle)
}
