package stats

import (
	"testing"
	"time"

	"github.com/gsmappdev/ctaudit/internal/waflog"
)

func TestWAFSummaryAddAndMerge(t *testing.T) {
	t1 := time.Date(2026, 9, 19, 14, 30, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 19, 14, 35, 0, 0, time.UTC)
	t3 := time.Date(2026, 9, 19, 16, 40, 0, 0, time.UTC)

	// First summary with a BLOCK entry
	s1 := NewWAFSummary()
	s1.Add(waflog.Entry{
		Time:            t1,
		WebACL:          "main-acl",
		Action:          "BLOCK",
		Rule:            "rule-1",
		RuleType:        "MANAGED",
		RuleGroup:       "AWSManagedRulesSQLiRuleSet",
		Source:          "source-1",
		ClientIP:        "203.0.113.9",
		Country:         "US",
		Method:          "POST",
		Host:            "api.example.com",
		URI:             "/users/42",
		UserAgent:       "curl/1.0",
		Labels:          []string{"label-1", "label-2"},
		CountRules:      []string{},
		RateRule:        "",
		ResponseCode:    403,
		Oversize:        false,
		JA4:             "ja4-value",
		ChallengeFailed: false,
	})

	// Second entry in first summary with an ALLOW and exploit match
	s1.Add(waflog.Entry{
		Time:            t2,
		WebACL:          "main-acl",
		Action:          "ALLOW",
		Rule:            "",
		RuleType:        "",
		RuleGroup:       "",
		Source:          "source-1",
		ClientIP:        "192.0.2.1",
		Country:         "UK",
		Method:          "GET",
		Host:            "api.example.com",
		URI:             "/users/99",
		UserAgent:       "chrome/1.0",
		Labels:          []string{"awswaf:managed:aws:sql-database:"},
		CountRules:      []string{"AWSManagedRulesSQLiRuleSet/rule-sql"},
		RateRule:        "",
		ResponseCode:    200,
		Oversize:        false,
		JA4:             "ja4-value-2",
		ChallengeFailed: false,
	})

	// Second summary with rate-limited and challenge-failed entries
	s2 := NewWAFSummary()
	s2.Add(waflog.Entry{
		Time:            t3,
		WebACL:          "backup-acl",
		Action:          "BLOCK",
		Rule:            "rate-limit-ip",
		RuleType:        "RATE_BASED",
		RuleGroup:       "rate-group",
		Source:          "source-2",
		ClientIP:        "203.0.113.9",
		Country:         "US",
		Method:          "POST",
		Host:            "api.example.com",
		URI:             "/api/123",
		UserAgent:       "bot/1.0",
		Labels:          []string{"label-3"},
		CountRules:      []string{},
		RateRule:        "rate-limit-ip",
		ResponseCode:    403,
		Oversize:        false,
		JA4:             "",
		ChallengeFailed: false,
	})

	// Oversize entry in s2
	s2.Add(waflog.Entry{
		Time:            t3,
		WebACL:          "main-acl",
		Action:          "BLOCK",
		Rule:            "rule-2",
		RuleType:        "MANAGED",
		RuleGroup:       "AWSManagedRulesCommonRuleSet",
		Source:          "source-1",
		ClientIP:        "198.51.100.5",
		Country:         "CA",
		Method:          "POST",
		Host:            "api.example.com",
		URI:             "/upload",
		UserAgent:       "app/1.0",
		Labels:          []string{},
		CountRules:      []string{},
		RateRule:        "",
		ResponseCode:    413,
		Oversize:        true,
		JA4:             "",
		ChallengeFailed: false,
	})

	// Merge s2 into s1
	s1.Merge(s2)

	// Check Total
	if s1.Total != 4 {
		t.Errorf("Total = %d, want 4", s1.Total)
	}

	// Check ByAction
	if s1.ByAction["BLOCK"] != 3 {
		t.Errorf("ByAction[BLOCK] = %d, want 3", s1.ByAction["BLOCK"])
	}
	if s1.ByAction["ALLOW"] != 1 {
		t.Errorf("ByAction[ALLOW] = %d, want 1", s1.ByAction["ALLOW"])
	}

	// Check ByRule counts only non-ALLOW entries
	if s1.ByRule["rule-1"] != 1 {
		t.Errorf("ByRule[rule-1] = %d, want 1", s1.ByRule["rule-1"])
	}
	if s1.ByRule["rate-limit-ip"] != 1 {
		t.Errorf("ByRule[rate-limit-ip] = %d, want 1", s1.ByRule["rate-limit-ip"])
	}
	if s1.ByRule["rule-2"] != 1 {
		t.Errorf("ByRule[rule-2] = %d, want 1", s1.ByRule["rule-2"])
	}
	if len(s1.ByRule) != 3 {
		t.Errorf("ByRule has %d entries, want 3 (no ALLOW rules)", len(s1.ByRule))
	}

	// Check ByBlockedIP counts only BLOCK
	if s1.ByBlockedIP["203.0.113.9"] != 2 {
		t.Errorf("ByBlockedIP[203.0.113.9] = %d, want 2", s1.ByBlockedIP["203.0.113.9"])
	}
	if s1.ByBlockedIP["192.0.2.1"] != 0 {
		t.Errorf("ByBlockedIP[192.0.2.1] should not exist (ALLOW), got %d", s1.ByBlockedIP["192.0.2.1"])
	}

	// Check ByURI normalizes paths
	if s1.ByURI["/users/{n}"] != 2 {
		t.Errorf("ByURI[/users/{n}] = %d, want 2", s1.ByURI["/users/{n}"])
	}

	// Check ByLabel counts each label
	if s1.ByLabel["label-1"] != 1 {
		t.Errorf("ByLabel[label-1] = %d, want 1", s1.ByLabel["label-1"])
	}
	if s1.ByLabel["label-2"] != 1 {
		t.Errorf("ByLabel[label-2] = %d, want 1", s1.ByLabel["label-2"])
	}
	if s1.ByLabel["label-3"] != 1 {
		t.Errorf("ByLabel[label-3] = %d, want 1", s1.ByLabel["label-3"])
	}

	// Check ByCountRule counts each COUNT rule
	if s1.ByCountRule["AWSManagedRulesSQLiRuleSet/rule-sql"] != 1 {
		t.Errorf("ByCountRule[AWSManagedRulesSQLiRuleSet/rule-sql] = %d, want 1", s1.ByCountRule["AWSManagedRulesSQLiRuleSet/rule-sql"])
	}

	// Check ByHour[t.Unix()/3600]
	h1 := t1.Unix() / 3600
	h3 := t3.Unix() / 3600
	if s1.ByHour[h1]["BLOCK"] != 1 {
		t.Errorf("ByHour[%d][BLOCK] = %d, want 1", h1, s1.ByHour[h1]["BLOCK"])
	}
	if s1.ByHour[h1]["ALLOW"] != 1 {
		t.Errorf("ByHour[%d][ALLOW] = %d, want 1", h1, s1.ByHour[h1]["ALLOW"])
	}
	if s1.ByHour[h3]["BLOCK"] != 2 {
		t.Errorf("ByHour[%d][BLOCK] = %d, want 2", h3, s1.ByHour[h3]["BLOCK"])
	}

	// Check IPs map
	ip1 := s1.IPs["203.0.113.9"]
	if ip1 == nil {
		t.Fatal("IPs[203.0.113.9] is nil")
	}
	if ip1.Blocks != 2 {
		t.Errorf("IPs[203.0.113.9].Blocks = %d, want 2", ip1.Blocks)
	}
	if ip1.Allows != 0 {
		t.Errorf("IPs[203.0.113.9].Allows = %d, want 0", ip1.Allows)
	}
	if ip1.RateLimited != 1 {
		t.Errorf("IPs[203.0.113.9].RateLimited = %d, want 1", ip1.RateLimited)
	}
	if ip1.ChallengeFails != 0 {
		t.Errorf("IPs[203.0.113.9].ChallengeFails = %d, want 0", ip1.ChallengeFails)
	}

	ip2 := s1.IPs["192.0.2.1"]
	if ip2 == nil {
		t.Fatal("IPs[192.0.2.1] is nil")
	}
	if ip2.Blocks != 0 {
		t.Errorf("IPs[192.0.2.1].Blocks = %d, want 0", ip2.Blocks)
	}
	if ip2.Allows != 1 {
		t.Errorf("IPs[192.0.2.1].Allows = %d, want 1", ip2.Allows)
	}

	// Check RateByRule maps a rate-based rule to the client IPs it limited
	if s1.RateByRule["rate-limit-ip"]["203.0.113.9"] != 1 {
		t.Errorf("RateByRule[rate-limit-ip][203.0.113.9] = %d, want 1", s1.RateByRule["rate-limit-ip"]["203.0.113.9"])
	}

	// Check Exploits gets an entry only for ALLOW with ExploitMatch()
	exploit := s1.Exploits["192.0.2.1"]
	if exploit == nil {
		t.Fatal("Exploits[192.0.2.1] is nil, but should exist")
	}
	if exploit.Count != 1 {
		t.Errorf("Exploits[192.0.2.1].Count = %d, want 1", exploit.Count)
	}
	if !exploit.First.Equal(t2) {
		t.Errorf("Exploits[192.0.2.1].First = %v, want %v", exploit.First, t2)
	}
	if exploit.URI != "/users/99" {
		t.Errorf("Exploits[192.0.2.1].URI = %q, want %q", exploit.URI, "/users/99")
	}

	// Check Oversize and OversizeIPs
	if s1.Oversize != 1 {
		t.Errorf("Oversize = %d, want 1", s1.Oversize)
	}
	if s1.OversizeIPs["198.51.100.5"] != 1 {
		t.Errorf("OversizeIPs[198.51.100.5] = %d, want 1", s1.OversizeIPs["198.51.100.5"])
	}

	// Check First and Last times
	if !s1.First.Equal(t1) {
		t.Errorf("First = %v, want %v", s1.First, t1)
	}
	if !s1.Last.Equal(t3) {
		t.Errorf("Last = %v, want %v", s1.Last, t3)
	}

	// Check BlockRate()
	expectedRate := 3.0 / 4.0
	if s1.BlockRate() != expectedRate {
		t.Errorf("BlockRate() = %f, want %f", s1.BlockRate(), expectedRate)
	}

	// Check Blocked()
	if s1.Blocked() != 3 {
		t.Errorf("Blocked() = %d, want 3", s1.Blocked())
	}
}

func TestWAFBlockRateWhenZero(t *testing.T) {
	s := NewWAFSummary()
	if s.BlockRate() != 0 {
		t.Errorf("BlockRate() on empty summary = %f, want 0", s.BlockRate())
	}
}

func TestWAFMergeIntoEmpty(t *testing.T) {
	t1 := time.Date(2026, 9, 19, 14, 30, 0, 0, time.UTC)

	empty := NewWAFSummary()
	other := NewWAFSummary()
	other.Add(waflog.Entry{
		Time:            t1,
		WebACL:          "test-acl",
		Action:          "BLOCK",
		Rule:            "rule-1",
		RuleType:        "MANAGED",
		RuleGroup:       "group-1",
		Source:          "source-1",
		ClientIP:        "10.0.0.1",
		Country:         "US",
		Method:          "POST",
		Host:            "example.com",
		URI:             "/test",
		UserAgent:       "test/1.0",
		Labels:          []string{},
		CountRules:      []string{},
		RateRule:        "",
		ResponseCode:    403,
		Oversize:        false,
		JA4:             "",
		ChallengeFailed: false,
	})

	empty.Merge(other)

	if empty.Total != 1 {
		t.Errorf("Total = %d, want 1", empty.Total)
	}
	if !empty.First.Equal(t1) || !empty.Last.Equal(t1) {
		t.Errorf("merging into an empty summary gave First=%v Last=%v, want both %v",
			empty.First, empty.Last, t1)
	}
}

func TestWAFChallengeFailure(t *testing.T) {
	t1 := time.Date(2026, 9, 19, 14, 30, 0, 0, time.UTC)

	s := NewWAFSummary()
	s.Add(waflog.Entry{
		Time:            t1,
		WebACL:          "test-acl",
		Action:          "BLOCK",
		Rule:            "challenge",
		RuleType:        "MANAGED",
		RuleGroup:       "group-1",
		Source:          "source-1",
		ClientIP:        "10.0.0.1",
		Country:         "US",
		Method:          "GET",
		Host:            "example.com",
		URI:             "/test",
		UserAgent:       "test/1.0",
		Labels:          []string{},
		CountRules:      []string{},
		RateRule:        "",
		ResponseCode:    403,
		Oversize:        false,
		JA4:             "",
		ChallengeFailed: true,
	})

	ip := s.IPs["10.0.0.1"]
	if ip == nil {
		t.Fatal("IPs[10.0.0.1] is nil")
	}
	if ip.ChallengeFails != 1 {
		t.Errorf("IPs[10.0.0.1].ChallengeFails = %d, want 1", ip.ChallengeFails)
	}
}

func TestWAFExploitsMergeTwoSided(t *testing.T) {
	t2 := time.Date(2026, 9, 19, 15, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 9, 19, 13, 0, 0, 0, time.UTC)

	// First summary: ALLOW with exploit match at t2
	s1 := NewWAFSummary()
	s1.Add(waflog.Entry{
		Time:            t2,
		WebACL:          "acl-1",
		Action:          "ALLOW",
		Rule:            "",
		RuleType:        "",
		RuleGroup:       "",
		Source:          "source-1",
		ClientIP:        "192.0.2.100",
		Country:         "US",
		Method:          "GET",
		Host:            "example.com",
		URI:             "/later",
		UserAgent:       "test/1.0",
		Labels:          []string{"awswaf:managed:aws:sql-database:"},
		CountRules:      []string{},
		RateRule:        "",
		ResponseCode:    200,
		Oversize:        false,
		JA4:             "",
		ChallengeFailed: false,
	})

	// Second summary: ALLOW with same exploit match at earlier time t3
	s2 := NewWAFSummary()
	s2.Add(waflog.Entry{
		Time:            t3,
		WebACL:          "acl-1",
		Action:          "ALLOW",
		Rule:            "",
		RuleType:        "",
		RuleGroup:       "",
		Source:          "source-2",
		ClientIP:        "192.0.2.100",
		Country:         "US",
		Method:          "POST",
		Host:            "example.com",
		URI:             "/earlier",
		UserAgent:       "test/2.0",
		Labels:          []string{"awswaf:managed:aws:sql-database:"},
		CountRules:      []string{},
		RateRule:        "",
		ResponseCode:    200,
		Oversize:        false,
		JA4:             "",
		ChallengeFailed: false,
	})

	// Merge s2 into s1
	s1.Merge(s2)

	// After merge, Exploits[192.0.2.100] should have:
	// - First = t3 (earliest)
	// - URI = "/earlier" (from earliest hit)
	// - Count = 2 (both exploits)
	exploit := s1.Exploits["192.0.2.100"]
	if exploit == nil {
		t.Fatal("Exploits[192.0.2.100] is nil")
	}
	if exploit.Count != 2 {
		t.Errorf("Exploits[192.0.2.100].Count = %d, want 2", exploit.Count)
	}
	if !exploit.First.Equal(t3) {
		t.Errorf("Exploits[192.0.2.100].First = %v, want %v (earliest)", exploit.First, t3)
	}
	if exploit.URI != "/earlier" {
		t.Errorf("Exploits[192.0.2.100].URI = %q, want %q (from earliest hit)", exploit.URI, "/earlier")
	}
	if exploit.Matches["awswaf:managed:aws:sql-database:"] != 2 {
		t.Errorf("Exploits[192.0.2.100].Matches[awswaf:managed:aws:sql-database:] = %d, want 2", exploit.Matches["awswaf:managed:aws:sql-database:"])
	}
}

func TestWAFExploitsMergeIntoEmpty(t *testing.T) {
	t1 := time.Date(2026, 9, 19, 14, 0, 0, 0, time.UTC)

	// Empty summary
	s1 := NewWAFSummary()

	// Second summary with exploit
	s2 := NewWAFSummary()
	s2.Add(waflog.Entry{
		Time:            t1,
		WebACL:          "acl-1",
		Action:          "ALLOW",
		Rule:            "",
		RuleType:        "",
		RuleGroup:       "",
		Source:          "source-1",
		ClientIP:        "192.0.2.200",
		Country:         "UK",
		Method:          "GET",
		Host:            "example.com",
		URI:             "/test",
		UserAgent:       "test/1.0",
		Labels:          []string{"awswaf:managed:aws:known-bad-inputs:"},
		CountRules:      []string{},
		RateRule:        "",
		ResponseCode:    200,
		Oversize:        false,
		JA4:             "",
		ChallengeFailed: false,
	})

	// Merge s2 into empty s1
	s1.Merge(s2)

	// Exploits should now exist in s1
	exploit := s1.Exploits["192.0.2.200"]
	if exploit == nil {
		t.Fatal("Exploits[192.0.2.200] is nil after merge into empty")
	}
	if exploit.Count != 1 {
		t.Errorf("Exploits[192.0.2.200].Count = %d, want 1", exploit.Count)
	}
	if !exploit.First.Equal(t1) {
		t.Errorf("Exploits[192.0.2.200].First = %v, want %v", exploit.First, t1)
	}
	if exploit.URI != "/test" {
		t.Errorf("Exploits[192.0.2.200].URI = %q, want %q", exploit.URI, "/test")
	}
}

func TestWAFIPsMergeTwoSided(t *testing.T) {
	// First summary: IP with some stats
	s1 := NewWAFSummary()
	s1.Add(waflog.Entry{
		Time:            time.Date(2026, 9, 19, 14, 0, 0, 0, time.UTC),
		WebACL:          "acl-1",
		Action:          "BLOCK",
		Rule:            "rule-1",
		RuleType:        "MANAGED",
		RuleGroup:       "group-1",
		Source:          "source-1",
		ClientIP:        "203.0.113.50",
		Country:         "US",
		Method:          "POST",
		Host:            "example.com",
		URI:             "/test",
		UserAgent:       "test/1.0",
		Labels:          []string{},
		CountRules:      []string{},
		RateRule:        "rate-1",
		ResponseCode:    403,
		Oversize:        false,
		JA4:             "",
		ChallengeFailed: true,
	})

	// Second summary: same IP with different stats
	s2 := NewWAFSummary()
	s2.Add(waflog.Entry{
		Time:            time.Date(2026, 9, 19, 15, 0, 0, 0, time.UTC),
		WebACL:          "acl-2",
		Action:          "ALLOW",
		Rule:            "",
		RuleType:        "",
		RuleGroup:       "",
		Source:          "source-2",
		ClientIP:        "203.0.113.50",
		Country:         "US",
		Method:          "GET",
		Host:            "example.com",
		URI:             "/api",
		UserAgent:       "test/2.0",
		Labels:          []string{},
		CountRules:      []string{},
		RateRule:        "rate-1",
		ResponseCode:    200,
		Oversize:        false,
		JA4:             "",
		ChallengeFailed: false,
	})

	// Merge s2 into s1
	s1.Merge(s2)

	// Check merged IP stats
	ip := s1.IPs["203.0.113.50"]
	if ip == nil {
		t.Fatal("IPs[203.0.113.50] is nil")
	}
	if ip.Blocks != 1 {
		t.Errorf("IPs[203.0.113.50].Blocks = %d, want 1", ip.Blocks)
	}
	if ip.Allows != 1 {
		t.Errorf("IPs[203.0.113.50].Allows = %d, want 1", ip.Allows)
	}
	if ip.RateLimited != 2 {
		t.Errorf("IPs[203.0.113.50].RateLimited = %d, want 2 (both rate-limited)", ip.RateLimited)
	}
	if ip.ChallengeFails != 1 {
		t.Errorf("IPs[203.0.113.50].ChallengeFails = %d, want 1", ip.ChallengeFails)
	}

	// Check RateByRule merge
	if s1.RateByRule["rate-1"]["203.0.113.50"] != 2 {
		t.Errorf("RateByRule[rate-1][203.0.113.50] = %d, want 2", s1.RateByRule["rate-1"]["203.0.113.50"])
	}
}
