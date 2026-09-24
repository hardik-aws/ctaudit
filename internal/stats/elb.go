package stats

import (
	"strconv"
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
)

// ELBSummary holds every aggregate the load balancer report needs. Like
// Summary, one goroutine owns it during a scan and shards are merged after.
type ELBSummary struct {
	Total         int
	ReceivedBytes int64
	SentBytes     int64
	Errors4xx     int
	Errors5xx     int
	// LatencyCount, LatencySum, and LatencyMax cover only entries whose
	// latency was measurable (Entry.Latency >= 0). Values are seconds.
	LatencyCount int
	LatencySum   float64
	LatencyMax   float64
	First        time.Time
	Last         time.Time

	ByLB           Counter
	ByType         Counter
	ByStatus       Counter
	ByTargetStatus Counter
	ByHost         Counter
	ByPath         Counter
	ByClientIP     Counter
	ByUserAgent    Counter
	ByTarget       Counter
	ByMethod       Counter
	BySSLProtocol  Counter
	BySSLCipher    Counter
	ByErrorReason  Counter
	ByAction       Counter
	ByHour         Counter
}

// NewELBSummary returns an ELBSummary with all counters initialised.
func NewELBSummary() *ELBSummary {
	return &ELBSummary{
		ByLB:           Counter{},
		ByType:         Counter{},
		ByStatus:       Counter{},
		ByTargetStatus: Counter{},
		ByHost:         Counter{},
		ByPath:         Counter{},
		ByClientIP:     Counter{},
		ByUserAgent:    Counter{},
		ByTarget:       Counter{},
		ByMethod:       Counter{},
		BySSLProtocol:  Counter{},
		BySSLCipher:    Counter{},
		ByErrorReason:  Counter{},
		ByAction:       Counter{},
		ByHour:         Counter{},
	}
}

// AvgLatency returns the mean measurable latency in seconds, or 0.
func (s *ELBSummary) AvgLatency() float64 {
	if s.LatencyCount == 0 {
		return 0
	}
	return s.LatencySum / float64(s.LatencyCount)
}

// Add folds one entry into the summary.
func (s *ELBSummary) Add(e elblog.Entry) {
	s.Total++
	s.ReceivedBytes += e.ReceivedBytes
	s.SentBytes += e.SentBytes
	switch {
	case strings.HasPrefix(e.ELBStatus, "4"):
		s.Errors4xx++
	case strings.HasPrefix(e.ELBStatus, "5"):
		s.Errors5xx++
	}
	if e.Latency >= 0 {
		s.LatencyCount++
		s.LatencySum += e.Latency
		if e.Latency > s.LatencyMax {
			s.LatencyMax = e.Latency
		}
	}
	if !e.Time.IsZero() {
		if s.First.IsZero() || e.Time.Before(s.First) {
			s.First = e.Time
		}
		if s.Last.IsZero() || e.Time.After(s.Last) {
			s.Last = e.Time
		}
		s.ByHour.add(strconv.Itoa(e.Time.UTC().Hour()))
	}

	s.ByLB.add(e.LB)
	s.ByType.add(e.Type)
	s.ByStatus.add(e.ELBStatus)
	s.ByTargetStatus.add(e.TargetStatus)
	s.ByHost.add(e.HostOrSNI())
	s.ByPath.add(NormalizePath(e.Path))
	s.ByClientIP.add(e.ClientIP)
	s.ByUserAgent.add(e.UserAgent)
	s.ByTarget.add(e.Target)
	s.ByMethod.add(e.Method)
	s.BySSLProtocol.add(e.SSLProtocol)
	s.BySSLCipher.add(e.SSLCipher)
	s.ByErrorReason.add(e.ErrorReason)
	s.ByAction.add(e.Actions)
}

// Merge folds another summary's totals into this one.
func (s *ELBSummary) Merge(other *ELBSummary) {
	if other == nil {
		return
	}
	s.Total += other.Total
	s.ReceivedBytes += other.ReceivedBytes
	s.SentBytes += other.SentBytes
	s.Errors4xx += other.Errors4xx
	s.Errors5xx += other.Errors5xx
	s.LatencyCount += other.LatencyCount
	s.LatencySum += other.LatencySum
	if other.LatencyMax > s.LatencyMax {
		s.LatencyMax = other.LatencyMax
	}
	if !other.First.IsZero() && (s.First.IsZero() || other.First.Before(s.First)) {
		s.First = other.First
	}
	if !other.Last.IsZero() && (s.Last.IsZero() || other.Last.After(s.Last)) {
		s.Last = other.Last
	}
	s.ByLB.merge(other.ByLB)
	s.ByType.merge(other.ByType)
	s.ByStatus.merge(other.ByStatus)
	s.ByTargetStatus.merge(other.ByTargetStatus)
	s.ByHost.merge(other.ByHost)
	s.ByPath.merge(other.ByPath)
	s.ByClientIP.merge(other.ByClientIP)
	s.ByUserAgent.merge(other.ByUserAgent)
	s.ByTarget.merge(other.ByTarget)
	s.ByMethod.merge(other.ByMethod)
	s.BySSLProtocol.merge(other.BySSLProtocol)
	s.BySSLCipher.merge(other.BySSLCipher)
	s.ByErrorReason.merge(other.ByErrorReason)
	s.ByAction.merge(other.ByAction)
	s.ByHour.merge(other.ByHour)
}

// NormalizePath replaces numeric path segments with "{n}" so that tile and
// ID paths (e.g. /tiles/14/2911/6346.pbf) group into one row instead of
// exploding the path counter. A numeric segment may carry an extension,
// which is kept: "6346.pbf" becomes "{n}.pbf".
func NormalizePath(p string) string {
	if p == "" {
		return ""
	}
	segs := strings.Split(p, "/")
	changed := false
	for i, seg := range segs {
		stem, ext := seg, ""
		if j := strings.IndexByte(seg, '.'); j >= 0 {
			stem, ext = seg[:j], seg[j:]
		}
		if stem == "" || !allDigits(stem) {
			continue
		}
		segs[i] = "{n}" + ext
		changed = true
	}
	if !changed {
		return p
	}
	return strings.Join(segs, "/")
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
