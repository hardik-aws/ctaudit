// Package ctevent models the CloudTrail log record schema and decodes the
// gzipped JSON objects that CloudTrail delivers to S3.
package ctevent

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Record is a single CloudTrail event. Fields we do not interpret are kept as
// json.RawMessage so that rules can inspect them lazily without paying the
// cost of decoding them for every record.
type Record struct {
	EventVersion        string          `json:"eventVersion"`
	EventTime           time.Time       `json:"eventTime"`
	EventSource         string          `json:"eventSource"`
	EventName           string          `json:"eventName"`
	AWSRegion           string          `json:"awsRegion"`
	SourceIPAddress     string          `json:"sourceIPAddress"`
	UserAgent           string          `json:"userAgent"`
	ErrorCode           string          `json:"errorCode"`
	ErrorMessage        string          `json:"errorMessage"`
	EventID             string          `json:"eventID"`
	EventType           string          `json:"eventType"`
	ReadOnly            *bool           `json:"readOnly"`
	ManagementEvent     *bool           `json:"managementEvent"`
	EventCategory       string          `json:"eventCategory"`
	RecipientAccountID  string          `json:"recipientAccountId"`
	UserIdentity        UserIdentity    `json:"userIdentity"`
	Resources           []Resource      `json:"resources"`
	RequestParameters   json.RawMessage `json:"requestParameters"`
	ResponseElements    json.RawMessage `json:"responseElements"`
	AdditionalEventData json.RawMessage `json:"additionalEventData"`
}

// UserIdentity describes the principal that made the API call.
type UserIdentity struct {
	Type           string          `json:"type"`
	PrincipalID    string          `json:"principalId"`
	ARN            string          `json:"arn"`
	AccountID      string          `json:"accountId"`
	AccessKeyID    string          `json:"accessKeyId"`
	UserName       string          `json:"userName"`
	InvokedBy      string          `json:"invokedBy"`
	SessionContext *SessionContext `json:"sessionContext"`
}

// SessionContext carries details about an assumed-role or federated session.
type SessionContext struct {
	Attributes    SessionAttributes `json:"attributes"`
	SessionIssuer *SessionIssuer    `json:"sessionIssuer"`
}

// SessionAttributes records how the session was established.
type SessionAttributes struct {
	MFAAuthenticated string `json:"mfaAuthenticated"`
	CreationDate     string `json:"creationDate"`
}

// SessionIssuer identifies the role or user behind an assumed-role session.
type SessionIssuer struct {
	Type      string `json:"type"`
	ARN       string `json:"arn"`
	UserName  string `json:"userName"`
	AccountID string `json:"accountId"`
}

// Resource is one entry of the record's resources array.
type Resource struct {
	ARN       string `json:"ARN"`
	AccountID string `json:"accountId"`
	Type      string `json:"type"`
}

// envelope is the outer shape of every CloudTrail object.
type envelope struct {
	Records []Record `json:"Records"`
}

// Actor returns the most human-meaningful identifier for the caller, falling
// back progressively when the richer fields are absent.
func (r Record) Actor() string {
	u := r.UserIdentity
	switch {
	case u.ARN != "":
		return u.ARN
	case u.InvokedBy != "":
		return u.InvokedBy
	case u.UserName != "":
		return u.UserName
	case u.PrincipalID != "":
		return u.PrincipalID
	default:
		return "unknown"
	}
}

// ServiceName strips the ".amazonaws.com" suffix from eventSource so that
// aggregations read as "ec2" rather than "ec2.amazonaws.com".
func (r Record) ServiceName() string {
	return strings.TrimSuffix(r.EventSource, ".amazonaws.com")
}

// readOnlyPrefixes are the verb prefixes AWS uses for non-mutating calls.
// They are only consulted when the record omits the readOnly field.
var readOnlyPrefixes = []string{"Describe", "Get", "List", "Lookup", "Search", "Query", "Head", "BatchGet", "Scan", "Select", "Assume", "Filter", "Estimate", "Validate", "Preview", "Simulate", "Check", "Test", "View", "Read", "Discover", "Resolve"}

// IsWrite reports whether the call mutated state. It trusts the readOnly field
// when present and otherwise infers from the event name's verb prefix.
func (r Record) IsWrite() bool {
	if r.ReadOnly != nil {
		return !*r.ReadOnly
	}
	for _, p := range readOnlyPrefixes {
		if strings.HasPrefix(r.EventName, p) {
			return false
		}
	}
	return r.EventName != ""
}

// DecodeGzip reads one gzipped CloudTrail object and returns its records.
func DecodeGzip(r io.Reader) ([]Record, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer zr.Close()

	var env envelope
	if err := json.NewDecoder(zr).Decode(&env); err != nil {
		return nil, fmt.Errorf("decode CloudTrail envelope: %w", err)
	}
	return env.Records, nil
}
