package s3src

import (
	"reflect"
	"testing"
	"time"
)

func TestVPCPrefixes(t *testing.T) {
	s := Scope{
		OrgID:      "o-1",
		Accounts:   []string{"111122223333"},
		Regions:    []string{"us-east-1", "eu-west-1"},
		Start:      time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
		End:        time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC),
		BasePrefix: "/flow/",
		Service:    ServiceVPC,
	}
	want := []string{
		"flow/AWSLogs/o-1/111122223333/vpcflowlogs/us-east-1/2026/09/20/",
		"flow/AWSLogs/o-1/111122223333/vpcflowlogs/us-east-1/2026/09/21/",
		"flow/AWSLogs/o-1/111122223333/vpcflowlogs/eu-west-1/2026/09/20/",
		"flow/AWSLogs/o-1/111122223333/vpcflowlogs/eu-west-1/2026/09/21/",
	}
	if got := s.Prefixes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Prefixes = %v\nwant %v", got, want)
	}
	s.OrgID, s.BasePrefix = "", ""
	if got := s.Prefixes()[0]; got != "AWSLogs/111122223333/vpcflowlogs/us-east-1/2026/09/20/" {
		t.Fatalf("plain prefix = %q", got)
	}
}

func TestVPCHivePrefix(t *testing.T) {
	s := Scope{BasePrefix: "/flow/", OrgID: "o-ignored"}
	if got, want := s.VPCHivePrefix("111122223333", "us-east-1"),
		"flow/AWSLogs/aws-account-id=111122223333/aws-service=vpcflowlogs/aws-region=us-east-1/"; got != want {
		t.Fatalf("VPCHivePrefix = %q, want %q", got, want)
	}
	if got, want := (Scope{}).VPCHivePrefix("111122223333", "eu-west-1"),
		"AWSLogs/aws-account-id=111122223333/aws-service=vpcflowlogs/aws-region=eu-west-1/"; got != want {
		t.Fatalf("VPCHivePrefix = %q, want %q", got, want)
	}
}
