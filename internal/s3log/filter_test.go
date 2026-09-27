package s3log

import (
	"testing"
	"time"
)

func TestFilterMatch(t *testing.T) {
	e := Entry{
		Time: time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC), Bucket: "data-bucket", RemoteIP: "203.0.113.9",
		Operation: "REST.DELETE.OBJECT", Key: "logs/app.log", Status: 204,
	}
	denied := Entry{Time: e.Time, Bucket: "data-bucket", Requester: "arn:aws:iam::111122223333:user/alice",
		Operation: "REST.GET.OBJECT", Key: "secrets/x", Status: 403, ErrorCode: "AccessDenied"}
	for _, tc := range []struct {
		name string
		f    Filter
		e    Entry
		want bool
	}{
		{"empty", Filter{}, e, true},
		{"operation substring fold", Filter{Operations: []string{"delete"}}, e, true},
		{"operation miss", Filter{Operations: []string{"PUT.OBJECT"}}, e, false},
		{"status exact", Filter{Statuses: []string{"204"}}, e, true},
		{"status class", Filter{Statuses: []string{"4XX"}}, denied, true},
		{"status miss", Filter{Statuses: []string{"200", "5xx"}}, e, false},
		{"requester anonymous", Filter{Requester: "anonymous"}, e, true},
		{"requester fold", Filter{Requester: "USER/ALICE"}, denied, true},
		{"requester miss", Filter{Requester: "bob"}, denied, false},
		{"client ip substring", Filter{ClientIP: "203.0."}, e, true},
		{"key prefix", Filter{KeyPrefix: "logs/"}, e, true},
		{"key prefix is case-sensitive", Filter{KeyPrefix: "Logs/"}, e, false},
		{"errors only drops 204", Filter{ErrorsOnly: true}, e, false},
		{"errors only keeps 403", Filter{ErrorsOnly: true}, denied, true},
		{"bucket fold", Filter{Buckets: []string{"DATA"}}, e, true},
		{"bucket miss", Filter{Buckets: []string{"web"}}, e, false},
		{"since inclusive", Filter{Since: e.Time}, e, true},
		{"until exclusive", Filter{Until: e.Time}, e, false},
	} {
		if got := tc.f.Match(tc.e); got != tc.want {
			t.Errorf("%s: Match = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFilterIsNarrowing(t *testing.T) {
	if (Filter{Since: time.Now(), Until: time.Now()}).IsNarrowing() {
		t.Fatal("time bounds alone are not narrowing")
	}
	for _, f := range []Filter{
		{Operations: []string{"x"}}, {Statuses: []string{"403"}}, {Requester: "x"}, {ClientIP: "1"},
		{KeyPrefix: "a"}, {ErrorsOnly: true}, {Buckets: []string{"b"}},
	} {
		if !f.IsNarrowing() {
			t.Errorf("%+v should be narrowing", f)
		}
	}
}
