package s3src

import (
	"reflect"
	"testing"
	"time"
)

func day(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func TestPrefixesOrgTrail(t *testing.T) {
	s := Scope{
		OrgID:    "o-abc123",
		Accounts: []string{"111122223333", "444455556666"},
		Regions:  []string{"us-east-1"},
		Start:    day(2026, time.September, 19),
		End:      day(2026, time.September, 20),
	}
	want := []string{
		"AWSLogs/o-abc123/111122223333/CloudTrail/us-east-1/2026/09/19/",
		"AWSLogs/o-abc123/111122223333/CloudTrail/us-east-1/2026/09/20/",
		"AWSLogs/o-abc123/444455556666/CloudTrail/us-east-1/2026/09/19/",
		"AWSLogs/o-abc123/444455556666/CloudTrail/us-east-1/2026/09/20/",
	}
	if got := s.Prefixes(); !reflect.DeepEqual(got, want) {
		t.Errorf("Prefixes() =\n%v\nwant\n%v", got, want)
	}
}

func TestPrefixesNonOrgTrailOmitsOrgID(t *testing.T) {
	s := Scope{
		Accounts: []string{"111122223333"},
		Regions:  []string{"eu-central-1"},
		Start:    day(2026, time.September, 20),
		End:      day(2026, time.September, 20),
	}
	want := []string{"AWSLogs/111122223333/CloudTrail/eu-central-1/2026/09/20/"}
	if got := s.Prefixes(); !reflect.DeepEqual(got, want) {
		t.Errorf("Prefixes() = %v, want %v", got, want)
	}
}

func TestPrefixesHonoursBasePrefix(t *testing.T) {
	s := Scope{
		BasePrefix: "logs/prod",
		Accounts:   []string{"111122223333"},
		Regions:    []string{"us-east-1"},
		Start:      day(2026, time.September, 20),
		End:        day(2026, time.September, 20),
	}
	want := []string{"logs/prod/AWSLogs/111122223333/CloudTrail/us-east-1/2026/09/20/"}
	if got := s.Prefixes(); !reflect.DeepEqual(got, want) {
		t.Errorf("Prefixes() = %v, want %v", got, want)
	}
}

func TestPrefixesCrossesMonthBoundary(t *testing.T) {
	s := Scope{
		Accounts: []string{"1"},
		Regions:  []string{"us-east-1"},
		Start:    day(2026, time.August, 31),
		End:      day(2026, time.September, 1),
	}
	want := []string{
		"AWSLogs/1/CloudTrail/us-east-1/2026/08/31/",
		"AWSLogs/1/CloudTrail/us-east-1/2026/09/01/",
	}
	if got := s.Prefixes(); !reflect.DeepEqual(got, want) {
		t.Errorf("Prefixes() = %v, want %v", got, want)
	}
}

func TestPrefixesEmptyWhenEndBeforeStart(t *testing.T) {
	s := Scope{
		Accounts: []string{"1"},
		Regions:  []string{"us-east-1"},
		Start:    day(2026, time.September, 20),
		End:      day(2026, time.September, 19),
	}
	if got := s.Prefixes(); len(got) != 0 {
		t.Errorf("Prefixes() = %v, want empty", got)
	}
}

func TestPrefixesEmptyWithoutAccountsOrRegions(t *testing.T) {
	base := Scope{Start: day(2026, time.September, 20), End: day(2026, time.September, 20)}

	noAccounts := base
	noAccounts.Regions = []string{"us-east-1"}
	if got := noAccounts.Prefixes(); len(got) != 0 {
		t.Errorf("Prefixes() with no accounts = %v, want empty", got)
	}

	noRegions := base
	noRegions.Accounts = []string{"1"}
	if got := noRegions.Prefixes(); len(got) != 0 {
		t.Errorf("Prefixes() with no regions = %v, want empty", got)
	}
}

func TestIsCloudTrailLogKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"AWSLogs/o-abc/1/CloudTrail/us-east-1/2026/09/20/1_CloudTrail_us-east-1_20260920T0000Z_ab12.json.gz", true},
		{"AWSLogs/o-abc/1/CloudTrail-Digest/us-east-1/2026/09/20/1_CloudTrail-Digest_x.json.gz", false},
		{"AWSLogs/o-abc/1/CloudTrail/us-east-1/2026/09/20/", false},
		{"AWSLogs/o-abc/1/CloudTrail/us-east-1/2026/09/20/notes.json", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := IsCloudTrailLogKey(tt.key); got != tt.want {
				t.Errorf("IsCloudTrailLogKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestPrefixesELBService(t *testing.T) {
	s := Scope{
		Service:    ServiceELB,
		BasePrefix: "/lb-logs/",
		Accounts:   []string{"111122223333"},
		Regions:    []string{"us-east-1"},
		Start:      day(2026, time.September, 23),
		End:        day(2026, time.September, 23),
	}
	want := []string{"lb-logs/AWSLogs/111122223333/elasticloadbalancing/us-east-1/2026/09/23/"}
	if got := s.Prefixes(); !reflect.DeepEqual(got, want) {
		t.Errorf("Prefixes() = %v, want %v", got, want)
	}
}
