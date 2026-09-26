package waflog

import (
	"testing"
	"time"
)

func TestFilterActions(t *testing.T) {
	e := Entry{Action: "BLOCK"}
	f := Filter{Actions: []string{"block"}}
	if !f.Match(e) {
		t.Error("should match BLOCK case-insensitively")
	}
	f = Filter{Actions: []string{"ALLOW"}}
	if f.Match(e) {
		t.Error("should not match ALLOW")
	}
}

func TestFilterClientIP(t *testing.T) {
	e := Entry{ClientIP: "203.0.113.9"}
	f := Filter{ClientIP: "203.0."}
	if !f.Match(e) {
		t.Error("should match subnet as substring")
	}
	f = Filter{ClientIP: "192.0."}
	if f.Match(e) {
		t.Error("should not match different subnet")
	}
}

func TestFilterCountries(t *testing.T) {
	e := Entry{Country: "NL"}
	f := Filter{Countries: []string{"nl"}}
	if !f.Match(e) {
		t.Error("should match country code case-insensitively")
	}
	f = Filter{Countries: []string{"US"}}
	if f.Match(e) {
		t.Error("should not match different country")
	}
}

func TestFilterRule(t *testing.T) {
	e := Entry{Rule: "AWSManagedRulesSQLiRuleSet/SQLi_QUERYARGUMENTS"}
	f := Filter{Rule: "sqli"}
	if !f.Match(e) {
		t.Error("should match rule as substring fold")
	}
	f = Filter{Rule: "SQLI"}
	if !f.Match(e) {
		t.Error("should match rule case-insensitively")
	}
	f = Filter{Rule: "xss"}
	if f.Match(e) {
		t.Error("should not match unrelated rule")
	}
}

func TestFilterURI(t *testing.T) {
	e := Entry{URI: "/login"}
	f := Filter{URI: "LOGIN"}
	if !f.Match(e) {
		t.Error("should match URI as substring fold")
	}
	f = Filter{URI: "/log"}
	if !f.Match(e) {
		t.Error("should match URI substring")
	}
	f = Filter{URI: "/register"}
	if f.Match(e) {
		t.Error("should not match different path")
	}
}

func TestFilterHost(t *testing.T) {
	e := Entry{Host: "web.example.com"}
	f := Filter{Host: "web."}
	if !f.Match(e) {
		t.Error("should match host as substring fold")
	}
	f = Filter{Host: "WEB."}
	if !f.Match(e) {
		t.Error("should match host case-insensitively")
	}
	f = Filter{Host: "api."}
	if f.Match(e) {
		t.Error("should not match different subdomain")
	}
}

func TestFilterTime(t *testing.T) {
	now := time.UnixMilli(1789900000123).UTC()
	e := Entry{Time: now}

	// Since is inclusive
	f := Filter{Since: now}
	if !f.Match(e) {
		t.Error("should match at Since boundary (inclusive)")
	}
	f = Filter{Since: now.Add(1 * time.Millisecond)}
	if f.Match(e) {
		t.Error("should not match before Since")
	}

	// Until is exclusive
	f = Filter{Until: now}
	if f.Match(e) {
		t.Error("should not match at Until boundary (exclusive)")
	}
	f = Filter{Until: now.Add(1 * time.Millisecond)}
	if !f.Match(e) {
		t.Error("should match before Until")
	}
}

func TestFilterIsNarrowing(t *testing.T) {
	// Time-only filter should not be narrowing
	f := Filter{Since: time.Now(), Until: time.Now().Add(1 * time.Hour)}
	if f.IsNarrowing() {
		t.Error("time-only filter should not be narrowing")
	}

	// Empty filter should not be narrowing
	f = Filter{}
	if f.IsNarrowing() {
		t.Error("empty filter should not be narrowing")
	}

	// Filter with any other field should be narrowing
	f = Filter{Actions: []string{"BLOCK"}}
	if !f.IsNarrowing() {
		t.Error("filter with Actions should be narrowing")
	}

	f = Filter{ClientIP: "10.0."}
	if !f.IsNarrowing() {
		t.Error("filter with ClientIP should be narrowing")
	}

	f = Filter{Countries: []string{"US"}}
	if !f.IsNarrowing() {
		t.Error("filter with Countries should be narrowing")
	}

	f = Filter{Rule: "sqli"}
	if !f.IsNarrowing() {
		t.Error("filter with Rule should be narrowing")
	}

	f = Filter{URI: "/login"}
	if !f.IsNarrowing() {
		t.Error("filter with URI should be narrowing")
	}

	f = Filter{Host: "web."}
	if !f.IsNarrowing() {
		t.Error("filter with Host should be narrowing")
	}
}

func TestFilterMultipleCriteria(t *testing.T) {
	e := Entry{
		Action:   "BLOCK",
		ClientIP: "203.0.113.9",
		Country:  "NL",
		Rule:     "AWSManagedRulesSQLiRuleSet/SQLi_QUERYARGUMENTS",
		URI:      "/login",
		Host:     "web.example.com",
		Time:     time.UnixMilli(1789900000123).UTC(),
	}

	// All match
	f := Filter{
		Actions:   []string{"block"},
		ClientIP:  "203.0.",
		Countries: []string{"nl"},
		Rule:      "sqli",
		URI:       "login",
		Host:      "web.",
		Since:     time.UnixMilli(1789900000122).UTC(),
		Until:     time.UnixMilli(1789900000124).UTC(),
	}
	if !f.Match(e) {
		t.Error("should match all criteria")
	}

	// One fails
	f = Filter{
		Actions:  []string{"allow"},
		ClientIP: "203.0.",
	}
	if f.Match(e) {
		t.Error("should fail when one criterion doesn't match")
	}
}
