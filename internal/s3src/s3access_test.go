package s3src

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestS3SimplePrefixes(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 9, d, 0, 0, 0, 0, time.UTC) }
	for _, tc := range []struct {
		base string
		want []string
	}{
		{"logs/", []string{"logs/2026-09-20-", "logs/2026-09-21-"}},
		{"access-", []string{"access-2026-09-20-", "access-2026-09-21-"}},
		{"", []string{"2026-09-20-", "2026-09-21-"}},
		{"/logs/", []string{"logs/2026-09-20-", "logs/2026-09-21-"}},
	} {
		s := Scope{BasePrefix: tc.base, Start: day(20), End: day(21)}
		if got := s.S3SimplePrefixes(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("base %q: got %v, want %v", tc.base, got, tc.want)
		}
	}
	if got := (Scope{Start: day(21), End: day(20)}).S3SimplePrefixes(); len(got) != 0 {
		t.Errorf("inverted range: got %v", got)
	}
}

func TestS3PartitionedPrefixes(t *testing.T) {
	m := NewMemStore(map[string][]byte{
		"logs/111122223333/us-east-1/data-bucket/2026/09/20/2026-09-20-10-15-02-A1B2C3D4E5F6A7B8": nil,
		"logs/111122223333/us-east-1/web-assets/2026/09/20/2026-09-20-10-15-02-B1B2C3D4E5F6A7B8":  nil,
		"logs/111122223333/eu-west-1/eu-data/2026/09/20/2026-09-20-10-15-02-C1B2C3D4E5F6A7B8":     nil,
		"logs/444455556666/us-east-1/other-acct/2026/09/20/2026-09-20-10-15-02-D1B2C3D4E5F6A7B8":  nil,
	})
	s := Scope{
		BasePrefix: "logs/", Accounts: []string{"111122223333"}, Regions: []string{"us-east-1", "eu-west-1"},
		Start: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC),
	}
	got, found, err := s.S3PartitionedPrefixes(context.Background(), m, []string{"DATA"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"logs/111122223333/us-east-1/data-bucket/2026/09/20/",
		"logs/111122223333/us-east-1/data-bucket/2026/09/21/",
		"logs/111122223333/eu-west-1/eu-data/2026/09/20/",
		"logs/111122223333/eu-west-1/eu-data/2026/09/21/",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixes = %v\nwant %v", got, want)
	}
	if !reflect.DeepEqual(found, []string{"data-bucket", "eu-data"}) {
		t.Fatalf("found = %v", found)
	}
	all, found, _ := s.S3PartitionedPrefixes(context.Background(), m, nil)
	if len(all) != 6 || len(found) != 3 {
		t.Fatalf("no filter: %d prefixes, found %v", len(all), found)
	}
	if none, _, _ := (Scope{Start: s.Start, End: s.End}).S3PartitionedPrefixes(context.Background(), m, nil); none != nil {
		t.Fatalf("no accounts: got %v", none)
	}
}

type dirsErrStore struct{ *MemStore }

func (dirsErrStore) ListDirs(context.Context, string) ([]string, error) {
	return nil, errors.New("access denied")
}

func TestS3PartitionedPrefixesListError(t *testing.T) {
	s := Scope{Accounts: []string{"111122223333"}, Regions: []string{"us-east-1"},
		Start: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)}
	_, _, err := s.S3PartitionedPrefixes(context.Background(), dirsErrStore{NewMemStore(nil)}, nil)
	if err == nil || !strings.Contains(err.Error(), "discover source buckets") {
		t.Fatalf("err = %v", err)
	}
}
