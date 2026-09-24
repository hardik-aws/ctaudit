package query

import (
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
)

func truthy(b bool) *bool { return &b }

func baseRecord() ctevent.Record {
	return ctevent.Record{
		EventTime:       time.Date(2026, 9, 19, 14, 19, 2, 0, time.UTC),
		EventSource:     "s3.amazonaws.com",
		EventName:       "DeleteBucket",
		AWSRegion:       "us-east-1",
		SourceIPAddress: "203.0.113.44",
		ReadOnly:        truthy(false),
		UserIdentity:    ctevent.UserIdentity{ARN: "arn:aws:iam::111122223333:user/alice"},
		Resources:       []ctevent.Resource{{ARN: "arn:aws:s3:::my-bucket", Type: "AWS::S3::Bucket"}},
	}
}

func TestEmptyFilterMatchesEverything(t *testing.T) {
	if !(Filter{}).Match(baseRecord()) {
		t.Error("empty Filter did not match; it must match every record")
	}
}

func TestFilterMatch(t *testing.T) {
	tests := []struct {
		name   string
		filter Filter
		mutate func(*ctevent.Record)
		want   bool
	}{
		{name: "principal substring matches", filter: Filter{Principal: "alice"}, want: true},
		{name: "principal is case insensitive", filter: Filter{Principal: "ALICE"}, want: true},
		{name: "principal mismatch", filter: Filter{Principal: "bob"}, want: false},
		{name: "resource substring matches", filter: Filter{Resource: "my-bucket"}, want: true},
		{name: "resource mismatch", filter: Filter{Resource: "other-bucket"}, want: false},
		{name: "source ip matches", filter: Filter{SourceIP: "203.0.113.44"}, want: true},
		{name: "source ip mismatch", filter: Filter{SourceIP: "10.0.0.1"}, want: false},
		{name: "event name matches exactly", filter: Filter{Events: []string{"DeleteBucket"}}, want: true},
		{name: "event name is case insensitive", filter: Filter{Events: []string{"deletebucket"}}, want: true},
		{name: "event name is not a substring match", filter: Filter{Events: []string{"Delete"}}, want: false},
		{name: "any event in the list matches", filter: Filter{Events: []string{"PutObject", "DeleteBucket"}}, want: true},
		{name: "source matches with suffix", filter: Filter{Sources: []string{"s3.amazonaws.com"}}, want: true},
		{name: "source matches short name", filter: Filter{Sources: []string{"s3"}}, want: true},
		{name: "source mismatch", filter: Filter{Sources: []string{"ec2"}}, want: false},
		{name: "writes only keeps writes", filter: Filter{WritesOnly: true}, want: true},
		{
			name:   "writes only drops reads",
			filter: Filter{WritesOnly: true},
			mutate: func(r *ctevent.Record) { r.ReadOnly = truthy(true); r.EventName = "ListBuckets" },
			want:   false,
		},
		{name: "errors only drops successes", filter: Filter{ErrorsOnly: true}, want: false},
		{
			name:   "errors only keeps failures",
			filter: Filter{ErrorsOnly: true},
			mutate: func(r *ctevent.Record) { r.ErrorCode = "AccessDenied" },
			want:   true,
		},
		{
			name:   "since excludes earlier events",
			filter: Filter{Since: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)},
			want:   false,
		},
		{
			name:   "since includes later events",
			filter: Filter{Since: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)},
			want:   true,
		},
		{
			name:   "until excludes later events",
			filter: Filter{Until: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)},
			want:   false,
		},
		{
			name:   "until includes earlier events",
			filter: Filter{Until: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)},
			want:   true,
		},
		{
			name:   "criteria are ANDed",
			filter: Filter{Principal: "alice", Resource: "other-bucket"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := baseRecord()
			if tt.mutate != nil {
				tt.mutate(&r)
			}
			if got := tt.filter.Match(r); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResourceAlsoMatchesRequestParameters(t *testing.T) {
	// Many events name the resource only in requestParameters, never in the
	// resources array, so the resource filter must look there too.
	r := baseRecord()
	r.Resources = nil
	r.RequestParameters = []byte(`{"bucketName":"my-bucket"}`)

	if !(Filter{Resource: "my-bucket"}).Match(r) {
		t.Error("resource filter did not match a name that appears only in requestParameters")
	}
}

func TestIsNarrowing(t *testing.T) {
	tests := []struct {
		name   string
		filter Filter
		want   bool
	}{
		{"empty", Filter{}, false},
		{"time bounds alone are not narrowing", Filter{Since: time.Now()}, false},
		{"writes only alone is not narrowing", Filter{WritesOnly: true}, false},
		{"principal narrows", Filter{Principal: "alice"}, true},
		{"resource narrows", Filter{Resource: "my-bucket"}, true},
		{"source ip narrows", Filter{SourceIP: "10.0.0.1"}, true},
		{"event list narrows", Filter{Events: []string{"DeleteBucket"}}, true},
		{"errors only narrows", Filter{ErrorsOnly: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.IsNarrowing(); got != tt.want {
				t.Errorf("IsNarrowing() = %v, want %v", got, tt.want)
			}
		})
	}
}
