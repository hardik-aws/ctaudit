package stats

import (
	"testing"

	"github.com/gsmappdev/ctaudit/internal/elblog"
)

func TestConnSummaryAddMerge(t *testing.T) {
	tls := elblog.Entry{Conn: true, ClientIP: "1.1.1.1", Listener: "443", SSLProtocol: "TLSv1.2",
		SSLCipher: "ECDHE-RSA-AES128-GCM-SHA256", TLSKeyExchange: "secp256r1",
		TLSVerifyStatus: "Success", TLSHandshakeTime: 0.2, LB: "app/lb/1"}
	failed := elblog.Entry{Conn: true, ClientIP: "2.2.2.2", Listener: "443", TLSHandshakeTime: -1, LB: "app/lb/1"}
	plain := elblog.Entry{Conn: true, ClientIP: "2.2.2.2", Listener: "80", TLSHandshakeTime: -1, LB: "app/lb/1"}

	a, b := NewConnSummary(), NewConnSummary()
	a.Add(tls)
	a.Add(failed)
	b.Add(plain)
	b.Add(elblog.Entry{Conn: true, Listener: "443", SSLProtocol: "TLSv1.3", TLSHandshakeTime: 0.6})
	a.Merge(b)
	a.Merge(nil)

	if a.Total != 4 || a.TLS != 2 || a.HandshakeFailed != 1 {
		t.Errorf("Total=%d TLS=%d Failed=%d", a.Total, a.TLS, a.HandshakeFailed)
	}
	if a.HandshakeCount != 2 || a.HandshakeMax != 0.6 || a.AvgHandshake() < 0.39 || a.AvgHandshake() > 0.41 {
		t.Errorf("handshake count=%d max=%v avg=%v", a.HandshakeCount, a.HandshakeMax, a.AvgHandshake())
	}
	if a.ByListenerTLS["443 no TLS"] != 1 || a.ByListenerTLS["80 no TLS"] != 1 || a.ByListenerTLS["443 TLSv1.2"] != 1 {
		t.Errorf("ByListenerTLS = %v", a.ByListenerTLS)
	}
	if a.ByFailedClientIP["2.2.2.2"] != 1 || a.ByClientIP["2.2.2.2"] != 2 {
		t.Errorf("client counters wrong: %v %v", a.ByFailedClientIP, a.ByClientIP)
	}
	if (&ConnSummary{}).AvgHandshake() != 0 {
		t.Error("empty avg")
	}
}
