// Package s3src turns an audit scope into concrete S3 key prefixes and reads
// the objects behind those prefixes.
package s3src

import (
	"fmt"
	"strings"
	"time"
)

// Scope describes which slice of a CloudTrail bucket an audit run covers.
// Start and End are inclusive calendar days in UTC.
type Scope struct {
	// OrgID is the organization ID path element, e.g. "o-abc123". Leave it
	// empty for a trail that is not an organization trail.
	OrgID string
	// Accounts are 12-digit AWS account IDs.
	Accounts []string
	// Regions are AWS region names, e.g. "us-east-1".
	Regions []string
	// Start and End bound the scan, inclusive, at day granularity.
	Start time.Time
	End   time.Time
	// BasePrefix is an optional key prefix configured on the trail, without
	// leading or trailing slashes.
	BasePrefix string
	// Service is the log-delivering service path element. Empty means
	// "CloudTrail"; Elastic Load Balancing access logs use
	// ServiceELB.
	Service string
}

// ServiceELB is the path element under which load balancers deliver access
// logs.
const ServiceELB = "elasticloadbalancing"

// Prefixes expands the scope into one S3 prefix per (account, region, day).
// This is what lets the tool avoid ever listing the bucket root: each returned
// prefix addresses at most a few dozen objects. Ordering is deterministic —
// account, then region, then day ascending — so runs are reproducible.
func (s Scope) Prefixes() []string {
	if len(s.Accounts) == 0 || len(s.Regions) == 0 {
		return nil
	}
	start := s.Start.UTC().Truncate(24 * time.Hour)
	end := s.End.UTC().Truncate(24 * time.Hour)
	if end.Before(start) {
		return nil
	}

	days := int(end.Sub(start)/(24*time.Hour)) + 1
	out := make([]string, 0, len(s.Accounts)*len(s.Regions)*days)

	service := s.Service
	if service == "" {
		service = "CloudTrail"
	}
	base := strings.Trim(s.BasePrefix, "/")
	for _, account := range s.Accounts {
		for _, region := range s.Regions {
			for d := 0; d < days; d++ {
				day := start.AddDate(0, 0, d)
				var b strings.Builder
				if base != "" {
					b.WriteString(base)
					b.WriteString("/")
				}
				b.WriteString("AWSLogs/")
				if s.OrgID != "" {
					b.WriteString(s.OrgID)
					b.WriteString("/")
				}
				fmt.Fprintf(&b, "%s/%s/%s/%04d/%02d/%02d/",
					account, service, region, day.Year(), int(day.Month()), day.Day())
				out = append(out, b.String())
			}
		}
	}
	return out
}

// IsCloudTrailLogKey reports whether a listed key is an event log object as
// opposed to a digest file, a directory placeholder, or stray content.
func IsCloudTrailLogKey(key string) bool {
	if !strings.HasSuffix(key, ".json.gz") {
		return false
	}
	if strings.Contains(key, "/CloudTrail-Digest/") {
		return false
	}
	return strings.Contains(key, "_CloudTrail_")
}
