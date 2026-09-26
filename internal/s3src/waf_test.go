package s3src

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestMemStoreListDirs(t *testing.T) {
	m := NewMemStore(map[string][]byte{
		"AWSLogs/1/WAFLogs/us-east-1/acl-a/2026/09/20/10/00/x.log.gz": nil,
		"AWSLogs/1/WAFLogs/us-east-1/acl-a/2026/09/21/10/00/y.log.gz": nil,
		"AWSLogs/1/WAFLogs/us-east-1/acl-b/2026/09/20/10/00/z.log.gz": nil,
		"AWSLogs/1/WAFLogs/us-east-1/stray.txt":                       nil,
	})
	got, err := m.ListDirs(context.Background(), "AWSLogs/1/WAFLogs/us-east-1/")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"AWSLogs/1/WAFLogs/us-east-1/acl-a/", "AWSLogs/1/WAFLogs/us-east-1/acl-b/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListDirs = %v, want %v", got, want)
	}
}

func TestWAFPrefixes(t *testing.T) {
	m := NewMemStore(map[string][]byte{
		"base/AWSLogs/o-1/111122223333/WAFLogs/us-east-1/prod-acl/2026/09/20/10/00/a.log.gz": nil,
		"base/AWSLogs/o-1/111122223333/WAFLogs/us-east-1/test-acl/2026/09/20/10/00/b.log.gz": nil,
		"base/AWSLogs/o-1/111122223333/WAFLogs/cloudfront/cf-acl/2026/09/20/10/00/c.log.gz":  nil,
	})
	s := Scope{
		OrgID: "o-1", Accounts: []string{"111122223333"}, Regions: []string{"us-east-1", "cloudfront"},
		Start: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC),
		BasePrefix: "/base/",
	}
	got, found, err := s.WAFPrefixes(context.Background(), m, []string{"PROD", "cf"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"base/AWSLogs/o-1/111122223333/WAFLogs/us-east-1/prod-acl/2026/09/20/",
		"base/AWSLogs/o-1/111122223333/WAFLogs/us-east-1/prod-acl/2026/09/21/",
		"base/AWSLogs/o-1/111122223333/WAFLogs/cloudfront/cf-acl/2026/09/20/",
		"base/AWSLogs/o-1/111122223333/WAFLogs/cloudfront/cf-acl/2026/09/21/",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixes = %v\nwant %v", got, want)
	}
	if !reflect.DeepEqual(found, []string{"cf-acl", "prod-acl"}) {
		t.Fatalf("found = %v", found)
	}
	all, found, _ := s.WAFPrefixes(context.Background(), m, nil)
	if len(all) != 6 || len(found) != 3 {
		t.Fatalf("no filter: %d prefixes, %v", len(all), found)
	}
}

func TestPrefixesUnchanged(t *testing.T) {
	s := Scope{Accounts: []string{"1"}, Regions: []string{"r"},
		Start: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}
	if got := s.Prefixes(); !reflect.DeepEqual(got, []string{"AWSLogs/1/CloudTrail/r/2026/01/02/"}) {
		t.Fatalf("Prefixes = %v", got)
	}
}
