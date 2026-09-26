package stats

import (
	"strconv"
	"time"

	"github.com/gsmappdev/ctaudit/internal/waflog"
)

// IPStats is the per-client detail the WAF findings need.
type IPStats struct {
	Blocks         int
	Allows         int
	RateLimited    int
	ChallengeFails int
}

// ExploitHit records allowed requests from one client that carried an
// exploit payload a COUNT-mode managed rule saw.
type ExploitHit struct {
	Count   int
	First   time.Time
	URI     string
	Matches Counter
}

// WAFSummary holds every aggregate the WAF report and findings need. One
// goroutine owns it during a scan; shards are merged after.
type WAFSummary struct {
	Total       int
	First, Last time.Time

	ByAction         Counter
	ByACL            Counter
	ByRule           Counter
	ByRuleGroup      Counter
	ByClientIP       Counter
	ByBlockedIP      Counter
	ByCountry        Counter
	ByBlockedCountry Counter
	ByHost           Counter
	ByURI            Counter
	ByMethod         Counter
	ByUserAgent      Counter
	BySource         Counter
	ByLabel          Counter
	ByCountRule      Counter
	ByJA4            Counter
	ByResponseCode   Counter

	// ByHour is keyed by Unix hour; each value counts actions.
	ByHour map[int64]Counter

	IPs         map[string]*IPStats
	RateByRule  map[string]Counter
	Exploits    map[string]*ExploitHit
	Oversize    int
	OversizeIPs Counter
}

// NewWAFSummary returns a WAFSummary with every map initialised.
func NewWAFSummary() *WAFSummary {
	return &WAFSummary{
		ByAction: Counter{}, ByACL: Counter{}, ByRule: Counter{}, ByRuleGroup: Counter{},
		ByClientIP: Counter{}, ByBlockedIP: Counter{}, ByCountry: Counter{}, ByBlockedCountry: Counter{},
		ByHost: Counter{}, ByURI: Counter{}, ByMethod: Counter{}, ByUserAgent: Counter{},
		BySource: Counter{}, ByLabel: Counter{}, ByCountRule: Counter{}, ByJA4: Counter{},
		ByResponseCode: Counter{},
		ByHour:         map[int64]Counter{},
		IPs:            map[string]*IPStats{},
		RateByRule:     map[string]Counter{},
		Exploits:       map[string]*ExploitHit{},
		OversizeIPs:    Counter{},
	}
}

// Blocked returns the number of blocked requests.
func (s *WAFSummary) Blocked() int { return s.ByAction["BLOCK"] }

// BlockRate returns the blocked share of all requests, or 0.
func (s *WAFSummary) BlockRate() float64 {
	if s.Total == 0 {
		return 0
	}
	return float64(s.Blocked()) / float64(s.Total)
}

func (s *WAFSummary) ip(addr string) *IPStats {
	st := s.IPs[addr]
	if st == nil {
		st = &IPStats{}
		s.IPs[addr] = st
	}
	return st
}

// Add folds one entry into the summary.
func (s *WAFSummary) Add(e waflog.Entry) {
	s.Total++
	if !e.Time.IsZero() {
		if s.First.IsZero() || e.Time.Before(s.First) {
			s.First = e.Time
		}
		if s.Last.IsZero() || e.Time.After(s.Last) {
			s.Last = e.Time
		}
		h := e.Time.Unix() / 3600
		if s.ByHour[h] == nil {
			s.ByHour[h] = Counter{}
		}
		s.ByHour[h].add(e.Action)
	}
	s.ByAction.add(e.Action)
	s.ByACL.add(e.WebACL)
	if e.Action != "ALLOW" {
		s.ByRule.add(e.Rule)
	}
	s.ByRuleGroup.add(e.RuleGroup)
	s.ByClientIP.add(e.ClientIP)
	s.ByCountry.add(e.Country)
	s.ByHost.add(e.Host)
	s.ByURI.add(NormalizePath(e.URI))
	s.ByMethod.add(e.Method)
	s.ByUserAgent.add(e.UserAgent)
	s.BySource.add(e.Source)
	s.ByJA4.add(e.JA4)
	if e.ResponseCode > 0 {
		s.ByResponseCode.add(strconv.Itoa(e.ResponseCode))
	}
	for _, l := range e.Labels {
		s.ByLabel.add(l)
	}
	for _, r := range e.CountRules {
		s.ByCountRule.add(r)
	}

	if e.ClientIP != "" {
		st := s.ip(e.ClientIP)
		switch e.Action {
		case "BLOCK":
			st.Blocks++
			s.ByBlockedIP.add(e.ClientIP)
			s.ByBlockedCountry.add(e.Country)
		case "ALLOW":
			st.Allows++
		}
		if e.RateRule != "" {
			st.RateLimited++
		}
		if e.ChallengeFailed {
			st.ChallengeFails++
		}
	}
	if e.RateRule != "" {
		if s.RateByRule[e.RateRule] == nil {
			s.RateByRule[e.RateRule] = Counter{}
		}
		s.RateByRule[e.RateRule].add(e.ClientIP)
	}
	if m := e.ExploitMatch(); m != "" {
		h := s.Exploits[e.ClientIP]
		if h == nil {
			h = &ExploitHit{Matches: Counter{}}
			s.Exploits[e.ClientIP] = h
		}
		h.Count++
		h.Matches.add(m)
		if h.First.IsZero() || e.Time.Before(h.First) {
			h.First, h.URI = e.Time, e.URI
		}
	}
	if e.Oversize {
		s.Oversize++
		s.OversizeIPs.add(e.ClientIP)
	}
}

// Merge folds another summary into this one.
func (s *WAFSummary) Merge(o *WAFSummary) {
	if o == nil {
		return
	}
	s.Total += o.Total
	if !o.First.IsZero() && (s.First.IsZero() || o.First.Before(s.First)) {
		s.First = o.First
	}
	if o.Last.After(s.Last) {
		s.Last = o.Last
	}
	for _, p := range [][2]Counter{
		{s.ByAction, o.ByAction}, {s.ByACL, o.ByACL}, {s.ByRule, o.ByRule}, {s.ByRuleGroup, o.ByRuleGroup},
		{s.ByClientIP, o.ByClientIP}, {s.ByBlockedIP, o.ByBlockedIP}, {s.ByCountry, o.ByCountry},
		{s.ByBlockedCountry, o.ByBlockedCountry}, {s.ByHost, o.ByHost}, {s.ByURI, o.ByURI},
		{s.ByMethod, o.ByMethod}, {s.ByUserAgent, o.ByUserAgent}, {s.BySource, o.BySource},
		{s.ByLabel, o.ByLabel}, {s.ByCountRule, o.ByCountRule}, {s.ByJA4, o.ByJA4},
		{s.ByResponseCode, o.ByResponseCode}, {s.OversizeIPs, o.OversizeIPs},
	} {
		p[0].merge(p[1])
	}
	for h, c := range o.ByHour {
		if s.ByHour[h] == nil {
			s.ByHour[h] = Counter{}
		}
		s.ByHour[h].merge(c)
	}
	for addr, st := range o.IPs {
		d := s.ip(addr)
		d.Blocks += st.Blocks
		d.Allows += st.Allows
		d.RateLimited += st.RateLimited
		d.ChallengeFails += st.ChallengeFails
	}
	for r, c := range o.RateByRule {
		if s.RateByRule[r] == nil {
			s.RateByRule[r] = Counter{}
		}
		s.RateByRule[r].merge(c)
	}
	for addr, h := range o.Exploits {
		d := s.Exploits[addr]
		if d == nil {
			d = &ExploitHit{Matches: Counter{}}
			s.Exploits[addr] = d
		}
		d.Count += h.Count
		d.Matches.merge(h.Matches)
		if d.First.IsZero() || (!h.First.IsZero() && h.First.Before(d.First)) {
			d.First, d.URI = h.First, h.URI
		}
	}
	s.Oversize += o.Oversize
}
