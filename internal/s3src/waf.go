package s3src

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
)

// WAFPrefixes discovers the web ACLs under each account and region, keeps
// those whose name contains one of acls (case-insensitive; empty keeps
// all), and returns one prefix per ACL and day. WAF files its logs under
// the ACL name before the date, so the names must be listed first. found
// is the sorted set of ACL names kept.
func (s Scope) WAFPrefixes(ctx context.Context, store ObjectStore, acls []string) ([]string, []string, error) {
	days := s.days()
	if len(s.Accounts) == 0 || len(s.Regions) == 0 || len(days) == 0 {
		return nil, nil, nil
	}
	var want []string
	for _, a := range acls {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			want = append(want, a)
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
			root := s.accountRoot(account) + ServiceWAF + "/" + region + "/"
			dirs, err := store.ListDirs(ctx, root)
			if err != nil {
				return nil, nil, fmt.Errorf("discover web ACLs: %w", err)
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
