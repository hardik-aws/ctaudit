package s3src

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Key layouts S3 server access logging can write, chosen per source bucket.
const (
	// S3LayoutSimple is <prefix>YYYY-MM-DD-hh-mm-ss-<unique>.
	S3LayoutSimple = "simple"
	// S3LayoutPartitioned is
	// <prefix><account>/<region>/<bucket>/YYYY/MM/DD/YYYY-MM-DD-hh-mm-ss-<unique>.
	S3LayoutPartitioned = "partitioned"
)

// s3Root is the target prefix server access logging writes under. S3
// appends the rest of the key to it directly, without a "/", so it is used
// verbatim; only a leading "/" is dropped, since keys never start with one.
// Unlike accountRoot, a trailing slash (or its absence) is preserved.
func (s Scope) s3Root() string {
	return strings.TrimLeft(s.BasePrefix, "/")
}

// S3SimplePrefixes returns one prefix per day for the simple layout:
// <prefix>YYYY-MM-DD-. Accounts and regions are not part of these keys.
func (s Scope) S3SimplePrefixes() []string {
	days := s.days()
	root := s.s3Root()
	out := make([]string, 0, len(days))
	for _, d := range days {
		out = append(out, fmt.Sprintf("%s%04d-%02d-%02d-", root, d.Year(), int(d.Month()), d.Day()))
	}
	return out
}

// S3PartitionedPrefixes discovers the source buckets under each account and
// region, keeps those whose name contains one of buckets (case-insensitive;
// empty keeps all), and returns one prefix per bucket and day. The bucket
// name sits before the date in the key, so it must be listed first. found
// is the sorted set of bucket names kept.
func (s Scope) S3PartitionedPrefixes(ctx context.Context, store ObjectStore, buckets []string) ([]string, []string, error) {
	days := s.days()
	if len(s.Accounts) == 0 || len(s.Regions) == 0 || len(days) == 0 {
		return nil, nil, nil
	}
	var want []string
	for _, b := range buckets {
		if b = strings.ToLower(strings.TrimSpace(b)); b != "" {
			want = append(want, b)
		}
	}
	keep := func(name string) bool {
		if len(want) == 0 {
			return true
		}
		lower := strings.ToLower(name)
		for _, w := range want {
			if strings.Contains(lower, w) {
				return true
			}
		}
		return false
	}

	var out []string
	names := map[string]bool{}
	for _, account := range s.Accounts {
		for _, region := range s.Regions {
			root := s.s3Root() + account + "/" + region + "/"
			dirs, err := store.ListDirs(ctx, root)
			if err != nil {
				return nil, nil, fmt.Errorf("discover source buckets: %w", err)
			}
			for _, dir := range dirs {
				name := path.Base(strings.TrimSuffix(dir, "/"))
				if !keep(name) {
					continue
				}
				names[name] = true
				for _, d := range days {
					out = append(out, fmt.Sprintf("%s%04d/%02d/%02d/", dir, d.Year(), int(d.Month()), d.Day()))
				}
			}
		}
	}
	found := make([]string, 0, len(names))
	for n := range names {
		found = append(found, n)
	}
	sort.Strings(found)
	return out, found, nil
}
