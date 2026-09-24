package stats

import (
	"time"

	"github.com/gsmappdev/ctaudit/internal/elblog"
)

// ConnSummary aggregates ALB connection log records. It is kept apart from
// ELBSummary so connections never inflate request totals.
type ConnSummary struct {
	Total int
	// TLS counts connections that negotiated a TLS protocol.
	TLS int
	// HandshakeFailed counts connections on port 443 that never completed a
	// TLS handshake (see elblog.Entry.HandshakeFailed).
	HandshakeFailed int
	// HandshakeCount, HandshakeSum, and HandshakeMax cover connections with
	// a measured handshake time. Values are seconds.
	HandshakeCount int
	HandshakeSum   float64
	HandshakeMax   float64
	// First and Last bound the connection times seen.
	First time.Time
	Last  time.Time

	ByLB          Counter
	ByListener    Counter
	ByListenerTLS Counter
	ByProtocol    Counter
	ByCipher      Counter
	ByKeyExchange Counter
	ByVerify      Counter
	ByClientIP    Counter
	// ByFailedClientIP counts HandshakeFailed connections per client.
	ByFailedClientIP Counter
}

// NewConnSummary returns a ConnSummary with all counters initialised.
func NewConnSummary() *ConnSummary {
	return &ConnSummary{
		ByLB:             Counter{},
		ByListener:       Counter{},
		ByListenerTLS:    Counter{},
		ByProtocol:       Counter{},
		ByCipher:         Counter{},
		ByKeyExchange:    Counter{},
		ByVerify:         Counter{},
		ByClientIP:       Counter{},
		ByFailedClientIP: Counter{},
	}
}

// AvgHandshake returns the mean measured handshake time in seconds, or 0.
func (s *ConnSummary) AvgHandshake() float64 {
	if s.HandshakeCount == 0 {
		return 0
	}
	return s.HandshakeSum / float64(s.HandshakeCount)
}

// Add folds one connection record into the summary.
func (s *ConnSummary) Add(e elblog.Entry) {
	s.Total++
	if !e.Time.IsZero() {
		if s.First.IsZero() || e.Time.Before(s.First) {
			s.First = e.Time
		}
		if s.Last.IsZero() || e.Time.After(s.Last) {
			s.Last = e.Time
		}
	}
	proto := e.SSLProtocol
	if proto != "" {
		s.TLS++
	} else {
		proto = "no TLS"
	}
	if e.HandshakeFailed() {
		s.HandshakeFailed++
		s.ByFailedClientIP.add(e.ClientIP)
	}
	if e.TLSHandshakeTime >= 0 {
		s.HandshakeCount++
		s.HandshakeSum += e.TLSHandshakeTime
		if e.TLSHandshakeTime > s.HandshakeMax {
			s.HandshakeMax = e.TLSHandshakeTime
		}
	}
	s.ByLB.add(e.LB)
	s.ByListener.add(e.Listener)
	if e.Listener != "" {
		s.ByListenerTLS.add(e.Listener + " " + proto)
	}
	s.ByProtocol.add(e.SSLProtocol)
	s.ByCipher.add(e.SSLCipher)
	s.ByKeyExchange.add(e.TLSKeyExchange)
	s.ByVerify.add(e.TLSVerifyStatus)
	s.ByClientIP.add(e.ClientIP)
}

// Merge folds another summary's totals into this one.
func (s *ConnSummary) Merge(other *ConnSummary) {
	if other == nil {
		return
	}
	s.Total += other.Total
	s.TLS += other.TLS
	s.HandshakeFailed += other.HandshakeFailed
	s.HandshakeCount += other.HandshakeCount
	s.HandshakeSum += other.HandshakeSum
	if other.HandshakeMax > s.HandshakeMax {
		s.HandshakeMax = other.HandshakeMax
	}
	if !other.First.IsZero() && (s.First.IsZero() || other.First.Before(s.First)) {
		s.First = other.First
	}
	if !other.Last.IsZero() && (s.Last.IsZero() || other.Last.After(s.Last)) {
		s.Last = other.Last
	}
	s.ByLB.merge(other.ByLB)
	s.ByListener.merge(other.ByListener)
	s.ByListenerTLS.merge(other.ByListenerTLS)
	s.ByProtocol.merge(other.ByProtocol)
	s.ByCipher.merge(other.ByCipher)
	s.ByKeyExchange.merge(other.ByKeyExchange)
	s.ByVerify.merge(other.ByVerify)
	s.ByClientIP.merge(other.ByClientIP)
	s.ByFailedClientIP.merge(other.ByFailedClientIP)
}
