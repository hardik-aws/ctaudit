package sink

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/findings"
)

// maxEventLine is the size above which a CloudTrail line is re-encoded
// without its bulky payload fields, to stay under Loki's default
// max_line_size of 256 KiB.
const maxEventLine = 128 << 10

// Encoder turns records into Loki labels and JSON lines. Job and Subcommand
// become labels on every line; RunID goes into every line.
type Encoder struct {
	Job        string
	Subcommand string
	RunID      string
}

func (e Encoder) labels(kind string, extra ...string) Labels {
	l := Labels{}
	set := func(k, v string) {
		if v != "" {
			l[k] = v
		}
	}
	set("job", e.Job)
	set("subcommand", e.Subcommand)
	set("kind", kind)
	for i := 0; i+1 < len(extra); i += 2 {
		set(extra[i], extra[i+1])
	}
	return l
}

type eventLine struct {
	Kind  string `json:"kind"`
	RunID string `json:"run_id"`
	ctevent.Record
	Truncated bool `json:"truncated,omitempty"`
}

// Event encodes a CloudTrail record. The line keeps CloudTrail's own field
// names.
func (e Encoder) Event(r ctevent.Record) (Labels, []byte) {
	labels := e.labels("event", "account", r.RecipientAccountID, "region", r.AWSRegion)
	line := eventLine{Kind: "event", RunID: e.RunID, Record: r}
	b, err := json.Marshal(line)
	if err != nil || len(b) > maxEventLine {
		line.RequestParameters = nil
		line.ResponseElements = nil
		line.AdditionalEventData = nil
		line.Truncated = true
		b, _ = json.Marshal(line)
	}
	return labels, b
}

type findingLine struct {
	Kind      string    `json:"kind"`
	RunID     string    `json:"run_id"`
	Rule      string    `json:"rule"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Actor     string    `json:"actor,omitempty"`
	Account   string    `json:"account,omitempty"`
	Region    string    `json:"region,omitempty"`
	EventID   string    `json:"event_id,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	EventTime time.Time `json:"event_time"`
}

// Finding encodes a CloudTrail finding.
func (e Encoder) Finding(f findings.Finding) (Labels, []byte) {
	sev := strings.ToLower(f.Severity.String())
	labels := e.labels("finding", "severity", sev, "account", f.Account)
	b, _ := json.Marshal(findingLine{
		Kind: "finding", RunID: e.RunID,
		Rule: f.Rule, Severity: sev, Title: f.Title, Actor: f.Actor,
		Account: f.Account, Region: f.Region, EventID: f.EventID,
		Detail: f.Detail, EventTime: f.Time,
	})
	return labels, b
}

type elbLine struct {
	Kind      string    `json:"kind"`
	RunID     string    `json:"run_id"`
	EventTime time.Time `json:"event_time"`
	LB        string    `json:"lb"`
	LBType    string    `json:"lb_type"`
	Type      string    `json:"type,omitempty"`

	ClientIP   string `json:"client_ip,omitempty"`
	ClientPort string `json:"client_port,omitempty"`
	Target     string `json:"target,omitempty"`

	RequestTime  *float64 `json:"request_time,omitempty"`
	TargetTime   *float64 `json:"target_time,omitempty"`
	ResponseTime *float64 `json:"response_time,omitempty"`
	Latency      *float64 `json:"latency,omitempty"`

	ELBStatus     string `json:"elb_status,omitempty"`
	TargetStatus  string `json:"target_status,omitempty"`
	ReceivedBytes int64  `json:"received_bytes"`
	SentBytes     int64  `json:"sent_bytes"`

	Method    string `json:"method,omitempty"`
	URL       string `json:"url,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Host      string `json:"host,omitempty"`
	Path      string `json:"path,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`

	SSLCipher   string `json:"ssl_cipher,omitempty"`
	SSLProtocol string `json:"ssl_protocol,omitempty"`

	TargetGroupARN       string `json:"target_group_arn,omitempty"`
	TraceID              string `json:"trace_id,omitempty"`
	DomainName           string `json:"domain_name,omitempty"`
	CertARN              string `json:"cert_arn,omitempty"`
	Actions              string `json:"actions,omitempty"`
	RedirectURL          string `json:"redirect_url,omitempty"`
	ErrorReason          string `json:"error_reason,omitempty"`
	Classification       string `json:"classification,omitempty"`
	ClassificationReason string `json:"classification_reason,omitempty"`
	ConnTraceID          string `json:"conn_trace_id,omitempty"`

	TLSVerifyStatus    string   `json:"tls_verify_status,omitempty"`
	ClientCertSubject  string   `json:"client_cert_subject,omitempty"`
	ClientCertValidity string   `json:"client_cert_validity,omitempty"`
	ClientCertSerial   string   `json:"client_cert_serial,omitempty"`
	Listener           string   `json:"listener,omitempty"`
	TLSHandshakeTime   *float64 `json:"tls_handshake_time,omitempty"`
	IncomingTLSAlert   string   `json:"incoming_tls_alert,omitempty"`
	TLSKeyExchange     string   `json:"tls_key_exchange,omitempty"`
	ALPNFrontend       string   `json:"alpn_frontend,omitempty"`
	ALPNBackend        string   `json:"alpn_backend,omitempty"`
}

// known returns nil for the -1 "not measured" sentinel.
func known(v float64) *float64 {
	if v < 0 {
		return nil
	}
	return &v
}

// ELB encodes a load balancer request, or a connection when x.Conn is set.
func (e Encoder) ELB(x elblog.Entry) (Labels, []byte) {
	kind := "request"
	if x.Conn {
		kind = "conn"
	}
	labels := e.labels(kind, "lb", x.LB)
	b, _ := json.Marshal(elbLine{
		Kind: kind, RunID: e.RunID, EventTime: x.Time, LB: x.LB, LBType: string(x.Kind), Type: x.Type,
		ClientIP: x.ClientIP, ClientPort: x.ClientPort, Target: x.Target,
		RequestTime: known(x.RequestTime), TargetTime: known(x.TargetTime),
		ResponseTime: known(x.ResponseTime), Latency: known(x.Latency),
		ELBStatus: x.ELBStatus, TargetStatus: x.TargetStatus,
		ReceivedBytes: x.ReceivedBytes, SentBytes: x.SentBytes,
		Method: x.Method, URL: x.URL, Protocol: x.Protocol, Host: x.Host, Path: x.Path, UserAgent: x.UserAgent,
		SSLCipher: x.SSLCipher, SSLProtocol: x.SSLProtocol,
		TargetGroupARN: x.TargetGroupARN, TraceID: x.TraceID, DomainName: x.DomainName, CertARN: x.CertARN,
		Actions: x.Actions, RedirectURL: x.RedirectURL, ErrorReason: x.ErrorReason,
		Classification: x.Classification, ClassificationReason: x.ClassificationReason, ConnTraceID: x.ConnTraceID,
		TLSVerifyStatus: x.TLSVerifyStatus, ClientCertSubject: x.ClientCertSubject,
		ClientCertValidity: x.ClientCertValidity, ClientCertSerial: x.ClientCertSerial,
		Listener: x.Listener, TLSHandshakeTime: known(x.TLSHandshakeTime), IncomingTLSAlert: x.IncomingTLSAlert,
		TLSKeyExchange: x.TLSKeyExchange, ALPNFrontend: x.ALPNFrontend, ALPNBackend: x.ALPNBackend,
	})
	return labels, b
}
