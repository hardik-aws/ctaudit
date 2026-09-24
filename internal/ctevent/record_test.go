package ctevent

import (
	"bytes"
	"compress/gzip"
	"testing"
	"time"
)

// gzipOf compresses s so tests can build CloudTrail objects in memory.
func gzipOf(t *testing.T, s string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

const sampleEnvelope = `{"Records":[
{"eventVersion":"1.08",
 "eventTime":"2026-09-17T02:14:09Z",
 "eventSource":"iam.amazonaws.com",
 "eventName":"CreateAccessKey",
 "awsRegion":"us-east-1",
 "sourceIPAddress":"203.0.113.44",
 "userAgent":"aws-cli/2.15.0",
 "eventID":"aaaa-1111",
 "eventType":"AwsApiCall",
 "readOnly":false,
 "managementEvent":true,
 "eventCategory":"Management",
 "recipientAccountId":"444455556666",
 "userIdentity":{"type":"Root","principalId":"444455556666","arn":"arn:aws:iam::444455556666:root","accountId":"444455556666"},
 "resources":[{"ARN":"arn:aws:iam::444455556666:user/contractor","accountId":"444455556666","type":"AWS::IAM::User"}],
 "requestParameters":{"userName":"contractor"}},
{"eventVersion":"1.08",
 "eventTime":"2026-09-17T02:15:00Z",
 "eventSource":"ec2.amazonaws.com",
 "eventName":"DescribeInstances",
 "awsRegion":"eu-central-1",
 "sourceIPAddress":"10.42.18.7",
 "eventID":"bbbb-2222",
 "eventType":"AwsApiCall",
 "readOnly":true,
 "recipientAccountId":"111122223333",
 "userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/argocd/session","accountId":"111122223333",
   "sessionContext":{"attributes":{"mfaAuthenticated":"false","creationDate":"2026-09-17T02:00:00Z"},
     "sessionIssuer":{"type":"Role","arn":"arn:aws:iam::111122223333:role/argocd","userName":"argocd","accountId":"111122223333"}}}}
]}`

func TestDecodeGzip(t *testing.T) {
	recs, err := DecodeGzip(gzipOf(t, sampleEnvelope))
	if err != nil {
		t.Fatalf("DecodeGzip: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}

	first := recs[0]
	wantTime := time.Date(2026, 9, 17, 2, 14, 9, 0, time.UTC)
	if !first.EventTime.Equal(wantTime) {
		t.Errorf("EventTime = %v, want %v", first.EventTime, wantTime)
	}
	if first.EventName != "CreateAccessKey" {
		t.Errorf("EventName = %q, want CreateAccessKey", first.EventName)
	}
	if first.ServiceName() != "iam" {
		t.Errorf("ServiceName() = %q, want iam", first.ServiceName())
	}
	if !first.IsWrite() {
		t.Error("IsWrite() = false, want true for readOnly:false")
	}
	if got := first.Actor(); got != "arn:aws:iam::444455556666:root" {
		t.Errorf("Actor() = %q, want the root ARN", got)
	}
	if len(first.Resources) != 1 || first.Resources[0].Type != "AWS::IAM::User" {
		t.Errorf("Resources = %+v, want one AWS::IAM::User", first.Resources)
	}

	second := recs[1]
	if second.IsWrite() {
		t.Error("IsWrite() = true, want false for readOnly:true")
	}
	if second.UserIdentity.SessionContext == nil {
		t.Fatal("SessionContext = nil, want it decoded")
	}
	if got := second.UserIdentity.SessionContext.Attributes.MFAAuthenticated; got != "false" {
		t.Errorf("MFAAuthenticated = %q, want false", got)
	}
	if got := second.UserIdentity.SessionContext.SessionIssuer.UserName; got != "argocd" {
		t.Errorf("SessionIssuer.UserName = %q, want argocd", got)
	}
}

func TestActorFallsBackWhenARNMissing(t *testing.T) {
	tests := []struct {
		name string
		in   Record
		want string
	}{
		{
			name: "arn wins",
			in:   Record{UserIdentity: UserIdentity{ARN: "arn:aws:iam::1:user/a", UserName: "a", PrincipalID: "AIDA1"}},
			want: "arn:aws:iam::1:user/a",
		},
		{
			name: "invokedBy for AWS services",
			in:   Record{UserIdentity: UserIdentity{Type: "AWSService", InvokedBy: "ec2.amazonaws.com"}},
			want: "ec2.amazonaws.com",
		},
		{
			name: "principalId when nothing else",
			in:   Record{UserIdentity: UserIdentity{PrincipalID: "AIDAEXAMPLE"}},
			want: "AIDAEXAMPLE",
		},
		{
			name: "unknown when empty",
			in:   Record{},
			want: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.Actor(); got != tt.want {
				t.Errorf("Actor() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsWriteUsesEventNameWhenReadOnlyAbsent(t *testing.T) {
	tests := []struct {
		eventName string
		want      bool
	}{
		{"DescribeInstances", false},
		{"GetObject", false},
		{"ListBuckets", false},
		{"LookupEvents", false},
		{"CreateBucket", true},
		{"DeleteTrail", true},
		{"AssumeRole", false},
	}
	for _, tt := range tests {
		t.Run(tt.eventName, func(t *testing.T) {
			r := Record{EventName: tt.eventName} // ReadOnly is nil
			if got := r.IsWrite(); got != tt.want {
				t.Errorf("IsWrite() for %s = %v, want %v", tt.eventName, got, tt.want)
			}
		})
	}
}

func TestDecodeGzipRejectsGarbage(t *testing.T) {
	if _, err := DecodeGzip(gzipOf(t, `{"Records": not json}`)); err == nil {
		t.Fatal("DecodeGzip returned nil error for malformed JSON")
	}
	if _, err := DecodeGzip(bytes.NewReader([]byte("not gzip at all"))); err == nil {
		t.Fatal("DecodeGzip returned nil error for non-gzip input")
	}
}
