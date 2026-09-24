package findings

import (
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
)

func at(h int) time.Time { return time.Date(2026, 9, 19, h, 0, 0, 0, time.UTC) }

// fire runs every default rule against r and returns the IDs that matched.
func fire(r ctevent.Record) map[string]Finding {
	out := map[string]Finding{}
	for _, rule := range DefaultRules() {
		if f, ok := rule.Check(r); ok {
			out[rule.ID()] = f
		}
	}
	return out
}

func TestRootUsageRule(t *testing.T) {
	r := ctevent.Record{
		EventTime:          at(2),
		EventName:          "CreateAccessKey",
		EventSource:        "iam.amazonaws.com",
		AWSRegion:          "us-east-1",
		RecipientAccountID: "444455556666",
		EventID:            "aaaa-1111",
		UserIdentity: ctevent.UserIdentity{
			Type: "Root",
			ARN:  "arn:aws:iam::444455556666:root",
		},
	}
	got := fire(r)

	f, ok := got["root-usage"]
	if !ok {
		t.Fatalf("root-usage did not fire; fired rules: %v", keys(got))
	}
	if f.Severity != SevCritical {
		t.Errorf("Severity = %v, want CRITICAL", f.Severity)
	}
	if f.Actor != "arn:aws:iam::444455556666:root" {
		t.Errorf("Actor = %q, want the root ARN", f.Actor)
	}
	if f.Account != "444455556666" || f.Region != "us-east-1" || f.EventID != "aaaa-1111" {
		t.Errorf("Finding did not carry account/region/eventID: %+v", f)
	}
	if !f.Time.Equal(at(2)) {
		t.Errorf("Time = %v, want %v", f.Time, at(2))
	}
}

func TestRootUsageIgnoresServiceCalledRootLikeNames(t *testing.T) {
	r := ctevent.Record{
		EventName:    "DescribeInstances",
		UserIdentity: ctevent.UserIdentity{Type: "AssumedRole", ARN: "arn:aws:sts::1:assumed-role/rootless"},
	}
	if _, ok := fire(r)["root-usage"]; ok {
		t.Error("root-usage fired on a non-Root identity")
	}
}

func TestConsoleLoginRules(t *testing.T) {
	noMFA := ctevent.Record{
		EventTime:           at(11),
		EventName:           "ConsoleLogin",
		EventSource:         "signin.amazonaws.com",
		SourceIPAddress:     "203.0.113.44",
		AdditionalEventData: []byte(`{"MFAUsed":"No"}`),
		ResponseElements:    []byte(`{"ConsoleLogin":"Success"}`),
		UserIdentity:        ctevent.UserIdentity{Type: "IAMUser", ARN: "arn:aws:iam::4:user/contractor"},
	}
	f, ok := fire(noMFA)["console-no-mfa"]
	if !ok {
		t.Fatal("console-no-mfa did not fire on a successful login with MFAUsed:No")
	}
	if f.Severity != SevHigh {
		t.Errorf("Severity = %v, want HIGH", f.Severity)
	}

	withMFA := noMFA
	withMFA.AdditionalEventData = []byte(`{"MFAUsed":"Yes"}`)
	if _, ok := fire(withMFA)["console-no-mfa"]; ok {
		t.Error("console-no-mfa fired even though MFAUsed was Yes")
	}

	failed := noMFA
	failed.ResponseElements = []byte(`{"ConsoleLogin":"Failure"}`)
	if _, ok := fire(failed)["console-login-failed"]; !ok {
		t.Error("console-login-failed did not fire on ConsoleLogin:Failure")
	}
	if _, ok := fire(failed)["console-no-mfa"]; ok {
		t.Error("console-no-mfa fired on a failed login; only successful logins matter")
	}
}

func TestAccessDeniedRule(t *testing.T) {
	r := ctevent.Record{
		EventTime:    at(9),
		EventName:    "DescribeInstances",
		ErrorCode:    "AccessDenied",
		UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
	}
	if _, ok := fire(r)["access-denied"]; !ok {
		t.Error("access-denied did not fire on errorCode AccessDenied")
	}

	r.ErrorCode = "UnauthorizedOperation"
	if _, ok := fire(r)["access-denied"]; !ok {
		t.Error("access-denied did not fire on errorCode UnauthorizedOperation")
	}

	r.ErrorCode = "NoSuchBucket"
	if _, ok := fire(r)["access-denied"]; ok {
		t.Error("access-denied fired on an unrelated error code")
	}
}

func TestIAMMutationAndAccessKeyRules(t *testing.T) {
	r := ctevent.Record{
		EventTime:    at(8),
		EventSource:  "iam.amazonaws.com",
		EventName:    "AttachUserPolicy",
		UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
	}
	f, ok := fire(r)["iam-mutation"]
	if !ok {
		t.Fatal("iam-mutation did not fire on AttachUserPolicy")
	}
	if f.Severity != SevMedium {
		t.Errorf("Severity = %v, want MEDIUM", f.Severity)
	}

	r.EventName = "ListUsers"
	if _, ok := fire(r)["iam-mutation"]; ok {
		t.Error("iam-mutation fired on a read-only IAM call")
	}

	r.EventName = "CreateAccessKey"
	got := fire(r)
	if _, ok := got["access-key-created"]; !ok {
		t.Error("access-key-created did not fire on CreateAccessKey")
	}
	if _, ok := got["iam-mutation"]; !ok {
		t.Error("iam-mutation should also fire on CreateAccessKey")
	}
}

func TestCloudTrailTamperRule(t *testing.T) {
	for _, name := range []string{"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"} {
		r := ctevent.Record{
			EventTime:    at(9),
			EventSource:  "cloudtrail.amazonaws.com",
			EventName:    name,
			UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
		}
		f, ok := fire(r)["cloudtrail-tamper"]
		if !ok {
			t.Errorf("cloudtrail-tamper did not fire on %s", name)
			continue
		}
		if f.Severity != SevCritical {
			t.Errorf("%s severity = %v, want CRITICAL", name, f.Severity)
		}
	}
}

func TestS3ExposureRule(t *testing.T) {
	for _, name := range []string{"PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy", "DeletePublicAccessBlock"} {
		r := ctevent.Record{
			EventTime:    at(9),
			EventSource:  "s3.amazonaws.com",
			EventName:    name,
			UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
		}
		if _, ok := fire(r)["s3-exposure"]; !ok {
			t.Errorf("s3-exposure did not fire on %s", name)
		}
	}

	safe := ctevent.Record{EventSource: "s3.amazonaws.com", EventName: "PutObject"}
	if _, ok := fire(safe)["s3-exposure"]; ok {
		t.Error("s3-exposure fired on PutObject")
	}
}

func TestOpenSecurityGroupRule(t *testing.T) {
	open := ctevent.Record{
		EventTime:         at(14),
		EventSource:       "ec2.amazonaws.com",
		EventName:         "AuthorizeSecurityGroupIngress",
		RequestParameters: []byte(`{"ipPermissions":{"items":[{"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]}}]}}`),
		UserIdentity:      ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
	}
	f, ok := fire(open)["sg-open-ingress"]
	if !ok {
		t.Fatal("sg-open-ingress did not fire on a 0.0.0.0/0 ingress rule")
	}
	if f.Severity != SevHigh {
		t.Errorf("Severity = %v, want HIGH", f.Severity)
	}

	closed := open
	closed.RequestParameters = []byte(`{"ipPermissions":{"items":[{"ipRanges":{"items":[{"cidrIp":"10.0.0.0/8"}]}}]}}`)
	if _, ok := fire(closed)["sg-open-ingress"]; ok {
		t.Error("sg-open-ingress fired on a private CIDR")
	}
}

func TestKMSDestructionRule(t *testing.T) {
	for _, name := range []string{"DisableKey", "ScheduleKeyDeletion"} {
		r := ctevent.Record{
			EventTime:    at(9),
			EventSource:  "kms.amazonaws.com",
			EventName:    name,
			UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
		}
		if _, ok := fire(r)["kms-destruction"]; !ok {
			t.Errorf("kms-destruction did not fire on %s", name)
		}
	}
}

func TestDetectorSortsBySeverityThenTime(t *testing.T) {
	d := NewDetector(DefaultRules())

	d.Inspect(ctevent.Record{ // MEDIUM, later
		EventTime: at(20), EventSource: "iam.amazonaws.com", EventName: "AttachUserPolicy",
		UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
	})
	d.Inspect(ctevent.Record{ // CRITICAL, earlier
		EventTime: at(3), EventSource: "cloudtrail.amazonaws.com", EventName: "StopLogging",
		UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
	})

	got := d.Findings()
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	if got[0].Rule != "cloudtrail-tamper" {
		t.Errorf("first finding = %q, want cloudtrail-tamper (CRITICAL sorts first)", got[0].Rule)
	}
	if got[1].Rule != "iam-mutation" {
		t.Errorf("second finding = %q, want iam-mutation", got[1].Rule)
	}
}

func TestDetectorMerge(t *testing.T) {
	a := NewDetector(DefaultRules())
	a.Inspect(ctevent.Record{
		EventTime: at(3), EventSource: "cloudtrail.amazonaws.com", EventName: "StopLogging",
		UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
	})

	b := NewDetector(DefaultRules())
	b.Inspect(ctevent.Record{
		EventTime: at(4), EventSource: "kms.amazonaws.com", EventName: "ScheduleKeyDeletion",
		UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/bob"},
	})

	a.Merge(b)
	if len(a.Findings()) != 2 {
		t.Fatalf("after Merge got %d findings, want 2", len(a.Findings()))
	}
}

func TestDetectorCapsFindings(t *testing.T) {
	d := NewDetector(DefaultRules())
	d.Max = 3
	for i := 0; i < 10; i++ {
		d.Inspect(ctevent.Record{
			EventTime: at(3), EventSource: "cloudtrail.amazonaws.com", EventName: "StopLogging",
			UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
		})
	}
	if got := len(d.Findings()); got != 3 {
		t.Errorf("got %d findings, want the cap of 3", got)
	}
	if d.Dropped != 7 {
		t.Errorf("Dropped = %d, want 7", d.Dropped)
	}
}

func TestDetectorRetainsHigherSeverityPastCap(t *testing.T) {
	d := NewDetector(DefaultRules())
	d.Max = 3
	for i := 0; i < 3; i++ {
		d.Inspect(ctevent.Record{
			EventTime: at(i), ErrorCode: "AccessDenied", EventName: "GetObject", EventSource: "s3.amazonaws.com",
			UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
		})
	}
	d.Inspect(ctevent.Record{ // CRITICAL, arrives after the cap is full of LOW findings.
		EventTime: at(9), EventSource: "cloudtrail.amazonaws.com", EventName: "StopLogging",
		UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
	})

	got := d.Findings()
	if len(got) != 3 {
		t.Fatalf("got %d findings, want the cap of 3", len(got))
	}
	found := false
	for _, f := range got {
		if f.Rule == "cloudtrail-tamper" {
			found = true
		}
	}
	if !found {
		t.Errorf("Findings() = %+v, want the CRITICAL cloudtrail-tamper finding retained", got)
	}
	if d.Dropped != 1 {
		t.Errorf("Dropped = %d, want 1", d.Dropped)
	}
	if d.MaxSeverity != SevCritical {
		t.Errorf("MaxSeverity = %v, want CRITICAL", d.MaxSeverity)
	}
	if !d.Seen {
		t.Errorf("Seen = false, want true")
	}
}

func TestDetectorMergeRetainsHigherSeverityPastCap(t *testing.T) {
	a := NewDetector(DefaultRules())
	a.Max = 2
	for i := 0; i < 2; i++ {
		a.Inspect(ctevent.Record{
			EventTime: at(i), ErrorCode: "AccessDenied", EventName: "GetObject", EventSource: "s3.amazonaws.com",
			UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
		})
	}

	b := NewDetector(DefaultRules())
	b.Max = 2
	b.Inspect(ctevent.Record{ // CRITICAL
		EventTime: at(9), EventSource: "cloudtrail.amazonaws.com", EventName: "StopLogging",
		UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/bob"},
	})

	a.Merge(b)

	got := a.Findings()
	if len(got) != 2 {
		t.Fatalf("got %d findings, want the cap of 2", len(got))
	}
	if got[0].Rule != "cloudtrail-tamper" {
		t.Errorf("first finding = %q, want cloudtrail-tamper (CRITICAL sorts first)", got[0].Rule)
	}
	if a.MaxSeverity != SevCritical {
		t.Errorf("MaxSeverity = %v, want CRITICAL", a.MaxSeverity)
	}
	if a.Dropped != 1 {
		t.Errorf("Dropped = %d, want 1", a.Dropped)
	}
}

func TestDetectorCapFullOfCriticalDropsLaterLow(t *testing.T) {
	d := NewDetector(DefaultRules())
	d.Max = 2
	for i := 0; i < 2; i++ {
		d.Inspect(ctevent.Record{
			EventTime: at(i), EventSource: "cloudtrail.amazonaws.com", EventName: "StopLogging",
			UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
		})
	}
	d.Inspect(ctevent.Record{ // LOW, arrives after the cap is full of CRITICAL findings.
		EventTime: at(9), ErrorCode: "AccessDenied", EventName: "GetObject", EventSource: "s3.amazonaws.com",
		UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
	})

	got := d.Findings()
	if len(got) != 2 {
		t.Fatalf("got %d findings, want the cap of 2", len(got))
	}
	for _, f := range got {
		if f.Rule != "cloudtrail-tamper" {
			t.Errorf("Findings() = %+v, want only cloudtrail-tamper retained", got)
		}
	}
	if d.MaxSeverity != SevCritical {
		t.Errorf("MaxSeverity = %v, want CRITICAL", d.MaxSeverity)
	}
	if d.Dropped != 1 {
		t.Errorf("Dropped = %d, want 1", d.Dropped)
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SevLow, "LOW"},
		{SevMedium, "MEDIUM"},
		{SevHigh, "HIGH"},
		{SevCritical, "CRITICAL"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func keys(m map[string]Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDetectorCountsIncludeDropped(t *testing.T) {
	stop := ctevent.Record{
		EventTime: at(3), EventSource: "cloudtrail.amazonaws.com", EventName: "StopLogging",
		UserIdentity: ctevent.UserIdentity{ARN: "arn:aws:iam::1:user/alice"},
	}
	a := NewDetector(DefaultRules())
	a.Max = 2
	for i := 0; i < 5; i++ {
		a.Inspect(stop)
	}
	sev := a.Findings()[0].Severity
	if a.Counts[sev] != 5 {
		t.Fatalf("Counts[%v] = %d, want 5 (dropped hits count too)", sev, a.Counts[sev])
	}

	b := NewDetector(DefaultRules())
	b.Inspect(stop)
	b.Inspect(stop)
	a.Merge(b)
	if a.Counts[sev] != 7 {
		t.Fatalf("after Merge Counts[%v] = %d, want 7", sev, a.Counts[sev])
	}
}
