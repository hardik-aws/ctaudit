package s3log

import (
	"strconv"
	"strings"
	"time"
)

// Filter selects S3 access log entries. Every criterion is optional; an
// entry must satisfy all of the ones that are set. Multi-value criteria
// match when any value matches.
type Filter struct {
	// Operations match the operation as case-insensitive substrings, so
	// "DELETE" matches every delete operation.
	Operations []string
	// Statuses are exact codes ("403") or classes ("4xx").
	Statuses []string
	// Requester matches Principal() as a case-insensitive substring;
	// "anonymous" selects unauthenticated requests.
	Requester string
	// ClientIP matches the remote IP as a substring.
	ClientIP string
	// KeyPrefix matches the start of the logged (URL-encoded) key,
	// case-sensitively like S3 keys.
	KeyPrefix string
	// ErrorsOnly keeps entries with status 400 or higher or an error code.
	ErrorsOnly bool
	// Buckets match the source bucket as case-insensitive substrings.
	Buckets []string
	// Since is inclusive, Until exclusive.
	Since time.Time
	Until time.Time
}

// Match reports whether the entry satisfies every criterion that is set.
func (f Filter) Match(e Entry) bool {
	if len(f.Operations) > 0 && !anyContainsFold(e.Operation, f.Operations) {
		return false
	}
	if len(f.Statuses) > 0 && !f.statusMatch(e) {
		return false
	}
	if f.Requester != "" && !containsFold(e.Principal(), f.Requester) {
		return false
	}
	if f.ClientIP != "" && !strings.Contains(e.RemoteIP, f.ClientIP) {
		return false
	}
	if f.KeyPrefix != "" && !strings.HasPrefix(e.Key, f.KeyPrefix) {
		return false
	}
	if f.ErrorsOnly && !e.IsError() {
		return false
	}
	if len(f.Buckets) > 0 && !anyContainsFold(e.Bucket, f.Buckets) {
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

func (f Filter) statusMatch(e Entry) bool {
	code := strconv.Itoa(e.Status)
	class := e.StatusClass()
	for _, s := range f.Statuses {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == code || s == class {
			return true
		}
	}
	return false
}

// IsNarrowing reports whether listing the individual matching requests is
// useful. Time bounds do not count.
func (f Filter) IsNarrowing() bool {
	return len(f.Operations) > 0 || len(f.Statuses) > 0 || f.Requester != "" || f.ClientIP != "" ||
		f.KeyPrefix != "" || f.ErrorsOnly || len(f.Buckets) > 0
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(strings.TrimSpace(needle)))
}

func anyContainsFold(value string, candidates []string) bool {
	for _, c := range candidates {
		if strings.TrimSpace(c) != "" && containsFold(value, c) {
			return true
		}
	}
	return false
}
