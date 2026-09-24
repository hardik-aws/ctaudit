package stats

import (
	"reflect"
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
)

func boolPtr(b bool) *bool { return &b }

func rec(actor, event, source, account, region, ip, errCode string, write bool, at time.Time) ctevent.Record {
	return ctevent.Record{
		EventTime:          at,
		EventName:          event,
		EventSource:        source,
		AWSRegion:          region,
		SourceIPAddress:    ip,
		ErrorCode:          errCode,
		ReadOnly:           boolPtr(!write),
		RecipientAccountID: account,
		UserIdentity:       ctevent.UserIdentity{ARN: actor},
	}
}

func TestSummaryAddCountsEverything(t *testing.T) {
	t1 := time.Date(2026, 9, 19, 14, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 19, 16, 0, 0, 0, time.UTC)

	s := NewSummary()
	s.Add(rec("alice", "DeleteBucket", "s3.amazonaws.com", "111", "us-east-1", "10.0.0.1", "", true, t1))
	s.Add(rec("alice", "GetObject", "s3.amazonaws.com", "111", "us-east-1", "10.0.0.1", "AccessDenied", false, t2))

	if s.TotalEvents != 2 {
		t.Errorf("TotalEvents = %d, want 2", s.TotalEvents)
	}
	if s.WriteEvents != 1 {
		t.Errorf("WriteEvents = %d, want 1", s.WriteEvents)
	}
	if s.ErrorEvents != 1 {
		t.Errorf("ErrorEvents = %d, want 1", s.ErrorEvents)
	}
	if !s.FirstEvent.Equal(t1) {
		t.Errorf("FirstEvent = %v, want %v", s.FirstEvent, t1)
	}
	if !s.LastEvent.Equal(t2) {
		t.Errorf("LastEvent = %v, want %v", s.LastEvent, t2)
	}
	if s.ByPrincipal["alice"] != 2 {
		t.Errorf("ByPrincipal[alice] = %d, want 2", s.ByPrincipal["alice"])
	}
	if s.ByService["s3"] != 2 {
		t.Errorf("ByService[s3] = %d, want 2 (suffix must be stripped)", s.ByService["s3"])
	}
	if s.ByAccount["111"] != 2 {
		t.Errorf("ByAccount[111] = %d, want 2", s.ByAccount["111"])
	}
	if s.ByRegion["us-east-1"] != 2 {
		t.Errorf("ByRegion[us-east-1] = %d, want 2", s.ByRegion["us-east-1"])
	}
	if s.ByErrorCode["AccessDenied"] != 1 {
		t.Errorf("ByErrorCode[AccessDenied] = %d, want 1", s.ByErrorCode["AccessDenied"])
	}
	if s.ByErrorCode[""] != 0 {
		t.Error("ByErrorCode must not count records with an empty error code")
	}
	if s.BySourceIP["10.0.0.1"] != 2 {
		t.Errorf("BySourceIP[10.0.0.1] = %d, want 2", s.BySourceIP["10.0.0.1"])
	}
	if s.ByHour["14"] != 1 || s.ByHour["16"] != 1 {
		t.Errorf("ByHour = %v, want one event in hour 14 and one in hour 16", s.ByHour)
	}
}

func TestSummaryMerge(t *testing.T) {
	early := time.Date(2026, 9, 18, 9, 0, 0, 0, time.UTC)
	late := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)

	a := NewSummary()
	a.Add(rec("alice", "GetObject", "s3.amazonaws.com", "111", "us-east-1", "10.0.0.1", "", false, late))

	b := NewSummary()
	b.Add(rec("bob", "GetObject", "s3.amazonaws.com", "222", "eu-central-1", "10.0.0.2", "AccessDenied", false, early))

	a.Merge(b)

	if a.TotalEvents != 2 {
		t.Errorf("TotalEvents = %d, want 2", a.TotalEvents)
	}
	if a.ErrorEvents != 1 {
		t.Errorf("ErrorEvents = %d, want 1", a.ErrorEvents)
	}
	if a.ByEventName["GetObject"] != 2 {
		t.Errorf("ByEventName[GetObject] = %d, want 2", a.ByEventName["GetObject"])
	}
	if a.ByPrincipal["bob"] != 1 {
		t.Errorf("ByPrincipal[bob] = %d, want 1 after merge", a.ByPrincipal["bob"])
	}
	if !a.FirstEvent.Equal(early) {
		t.Errorf("FirstEvent = %v, want the earlier time %v", a.FirstEvent, early)
	}
	if !a.LastEvent.Equal(late) {
		t.Errorf("LastEvent = %v, want the later time %v", a.LastEvent, late)
	}
}

func TestMergeIntoEmptySummaryKeepsTimes(t *testing.T) {
	at := time.Date(2026, 9, 18, 9, 0, 0, 0, time.UTC)

	empty := NewSummary()
	other := NewSummary()
	other.Add(rec("alice", "GetObject", "s3.amazonaws.com", "111", "us-east-1", "10.0.0.1", "", false, at))

	empty.Merge(other)

	if !empty.FirstEvent.Equal(at) || !empty.LastEvent.Equal(at) {
		t.Errorf("merging into an empty summary gave First=%v Last=%v, want both %v",
			empty.FirstEvent, empty.LastEvent, at)
	}
}

func TestCounterTopN(t *testing.T) {
	c := Counter{"a": 5, "b": 9, "c": 5, "d": 1}

	got := c.TopN(3)
	want := []Pair{{Key: "b", Count: 9}, {Key: "a", Count: 5}, {Key: "c", Count: 5}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TopN(3) = %v, want %v (ties break on key ascending)", got, want)
	}

	if got := c.TopN(100); len(got) != 4 {
		t.Errorf("TopN(100) returned %d entries, want all 4", len(got))
	}
	if got := c.TopN(0); len(got) != 0 {
		t.Errorf("TopN(0) returned %d entries, want 0", len(got))
	}
}
