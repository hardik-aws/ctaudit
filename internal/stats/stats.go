// Package stats aggregates CloudTrail records into per-dimension counts.
// A Summary is owned by exactly one goroutine while a scan runs; the shards
// are combined with Merge once the scan finishes.
package stats

import (
	"sort"
	"strconv"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
)

// Counter tallies occurrences by key.
type Counter map[string]int

// Pair is one counter entry, used for ranked output.
type Pair struct {
	Key   string
	Count int
}

// TopN returns the n highest-count entries, breaking ties on key ascending so
// that repeated runs over the same data produce identical reports.
func (c Counter) TopN(n int) []Pair {
	if n <= 0 {
		return nil
	}
	pairs := make([]Pair, 0, len(c))
	for k, v := range c {
		pairs = append(pairs, Pair{Key: k, Count: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count != pairs[j].Count {
			return pairs[i].Count > pairs[j].Count
		}
		return pairs[i].Key < pairs[j].Key
	})
	if len(pairs) > n {
		pairs = pairs[:n]
	}
	return pairs
}

func (c Counter) add(key string) {
	if key != "" {
		c[key]++
	}
}

func (c Counter) merge(other Counter) {
	for k, v := range other {
		c[k] += v
	}
}

// Summary holds every aggregate the report needs.
type Summary struct {
	TotalEvents int
	WriteEvents int
	ErrorEvents int
	FirstEvent  time.Time
	LastEvent   time.Time

	ByPrincipal Counter
	ByEventName Counter
	ByService   Counter
	ByAccount   Counter
	ByRegion    Counter
	ByErrorCode Counter
	BySourceIP  Counter
	ByHour      Counter
}

// NewSummary returns a Summary with all counters initialised.
func NewSummary() *Summary {
	return &Summary{
		ByPrincipal: Counter{},
		ByEventName: Counter{},
		ByService:   Counter{},
		ByAccount:   Counter{},
		ByRegion:    Counter{},
		ByErrorCode: Counter{},
		BySourceIP:  Counter{},
		ByHour:      Counter{},
	}
}

// Add folds one record into the summary.
func (s *Summary) Add(r ctevent.Record) {
	s.TotalEvents++
	if r.IsWrite() {
		s.WriteEvents++
	}
	if r.ErrorCode != "" {
		s.ErrorEvents++
	}

	if !r.EventTime.IsZero() {
		if s.FirstEvent.IsZero() || r.EventTime.Before(s.FirstEvent) {
			s.FirstEvent = r.EventTime
		}
		if s.LastEvent.IsZero() || r.EventTime.After(s.LastEvent) {
			s.LastEvent = r.EventTime
		}
		s.ByHour.add(strconv.Itoa(r.EventTime.UTC().Hour()))
	}

	s.ByPrincipal.add(r.Actor())
	s.ByEventName.add(r.EventName)
	s.ByService.add(r.ServiceName())
	s.ByAccount.add(r.RecipientAccountID)
	s.ByRegion.add(r.AWSRegion)
	s.ByErrorCode.add(r.ErrorCode)
	s.BySourceIP.add(r.SourceIPAddress)
}

// Merge folds another summary's totals into this one.
func (s *Summary) Merge(other *Summary) {
	if other == nil {
		return
	}
	s.TotalEvents += other.TotalEvents
	s.WriteEvents += other.WriteEvents
	s.ErrorEvents += other.ErrorEvents

	if !other.FirstEvent.IsZero() && (s.FirstEvent.IsZero() || other.FirstEvent.Before(s.FirstEvent)) {
		s.FirstEvent = other.FirstEvent
	}
	if !other.LastEvent.IsZero() && (s.LastEvent.IsZero() || other.LastEvent.After(s.LastEvent)) {
		s.LastEvent = other.LastEvent
	}

	s.ByPrincipal.merge(other.ByPrincipal)
	s.ByEventName.merge(other.ByEventName)
	s.ByService.merge(other.ByService)
	s.ByAccount.merge(other.ByAccount)
	s.ByRegion.merge(other.ByRegion)
	s.ByErrorCode.merge(other.ByErrorCode)
	s.BySourceIP.merge(other.BySourceIP)
	s.ByHour.merge(other.ByHour)
}
