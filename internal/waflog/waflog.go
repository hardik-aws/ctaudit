// Package waflog decodes AWS WAF logs delivered to S3: gzipped JSON, one
// request per line. Only the fields the reports need are kept; every header
// except Host and User-Agent, the query string, and any body are dropped
// here so they can never reach a report or a sink.
package waflog

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Entry is one WAF-inspected request.
type Entry struct {
	Time      time.Time
	WebACL    string
	Action    string
	Rule      string
	RuleType  string
	RuleGroup string
	Source    string
	SourceID  string

	ClientIP  string
	Country   string
	Method    string
	Host      string
	URI       string
	UserAgent string

	Labels     []string
	CountRules []string
	RateRule   string

	ResponseCode    int
	Oversize        bool
	JA3             string
	JA4             string
	RequestID       string
	ChallengeFailed bool
}

type rawRule struct {
	RuleID string `json:"ruleId"`
	Action string `json:"action"`
}

type rawChallenge struct {
	ResponseCode  int    `json:"responseCode"`
	FailureReason string `json:"failureReason"`
}

type rawRecord struct {
	Timestamp           int64  `json:"timestamp"`
	WebACLID            string `json:"webaclId"`
	TerminatingRuleID   string `json:"terminatingRuleId"`
	TerminatingRuleType string `json:"terminatingRuleType"`
	Action              string `json:"action"`
	HTTPSourceName      string `json:"httpSourceName"`
	HTTPSourceID        string `json:"httpSourceId"`
	RuleGroupList       []struct {
		RuleGroupID     string    `json:"ruleGroupId"`
		TerminatingRule *rawRule  `json:"terminatingRule"`
		NonTerminating  []rawRule `json:"nonTerminatingMatchingRules"`
		ExcludedRules   []struct {
			RuleID string `json:"ruleId"`
		} `json:"excludedRules"`
	} `json:"ruleGroupList"`
	NonTerminating   []rawRule `json:"nonTerminatingMatchingRules"`
	ResponseCodeSent int       `json:"responseCodeSent"`
	HTTPRequest      struct {
		ClientIP string `json:"clientIp"`
		Country  string `json:"country"`
		Headers  []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
		URI        string `json:"uri"`
		HTTPMethod string `json:"httpMethod"`
		RequestID  string `json:"requestId"`
	} `json:"httpRequest"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
	CaptchaResponse   *rawChallenge `json:"captchaResponse"`
	ChallengeResponse *rawChallenge `json:"challengeResponse"`
	OversizeFields    []string      `json:"oversizeFields"`
	JA3               string        `json:"ja3Fingerprint"`
	JA4               string        `json:"ja4Fingerprint"`
}

// Parse decodes one JSON log line.
func Parse(line []byte) (Entry, error) {
	var r rawRecord
	if err := json.Unmarshal(line, &r); err != nil {
		return Entry{}, err
	}
	if r.Timestamp == 0 || r.Action == "" {
		return Entry{}, errors.New("not a WAF log record: missing timestamp or action")
	}
	e := Entry{
		Time:         time.UnixMilli(r.Timestamp).UTC(),
		WebACL:       aclName(r.WebACLID),
		Action:       r.Action,
		Rule:         r.TerminatingRuleID,
		RuleType:     r.TerminatingRuleType,
		Source:       r.HTTPSourceName,
		SourceID:     r.HTTPSourceID,
		ClientIP:     r.HTTPRequest.ClientIP,
		Country:      r.HTTPRequest.Country,
		Method:       r.HTTPRequest.HTTPMethod,
		URI:          r.HTTPRequest.URI,
		RequestID:    r.HTTPRequest.RequestID,
		ResponseCode: r.ResponseCodeSent,
		Oversize:     len(r.OversizeFields) > 0,
		JA3:          r.JA3,
		JA4:          r.JA4,
	}
	for _, h := range r.HTTPRequest.Headers {
		switch strings.ToLower(h.Name) {
		case "host":
			e.Host = h.Value
		case "user-agent":
			e.UserAgent = h.Value
		}
	}
	for _, l := range r.Labels {
		if l.Name != "" {
			e.Labels = append(e.Labels, l.Name)
		}
	}
	for _, g := range r.RuleGroupList {
		group := groupName(g.RuleGroupID)
		if g.TerminatingRule != nil && g.TerminatingRule.RuleID != "" && e.RuleGroup == "" {
			e.RuleGroup = group
			e.Rule = group + "/" + g.TerminatingRule.RuleID
		}
		for _, nt := range g.NonTerminating {
			if strings.EqualFold(nt.Action, "COUNT") {
				e.CountRules = append(e.CountRules, group+"/"+nt.RuleID)
			}
		}
		for _, ex := range g.ExcludedRules {
			if ex.RuleID != "" {
				e.CountRules = append(e.CountRules, group+"/"+ex.RuleID)
			}
		}
	}
	for _, nt := range r.NonTerminating {
		if strings.EqualFold(nt.Action, "COUNT") {
			e.CountRules = append(e.CountRules, nt.RuleID)
		}
	}
	if r.TerminatingRuleType == "RATE_BASED" {
		e.RateRule = r.TerminatingRuleID
	}
	e.ChallengeFailed = failed(r.CaptchaResponse) || failed(r.ChallengeResponse)
	return e, nil
}

func failed(c *rawChallenge) bool {
	if c == nil {
		return false
	}
	return c.FailureReason != "" || (c.ResponseCode != 0 && (c.ResponseCode < 200 || c.ResponseCode >= 300))
}

// aclName returns the web ACL name from its ARN
// (arn:aws:wafv2:<region>:<acct>:<scope>/webacl/<name>/<id>).
func aclName(arn string) string {
	if i := strings.Index(arn, "/webacl/"); i >= 0 {
		rest := arn[i+len("/webacl/"):]
		if j := strings.Index(rest, "/"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return arn
}

// groupName shortens a rule group ID: "AWS#AWSManagedRulesSQLiRuleSet"
// becomes "AWSManagedRulesSQLiRuleSet", and a custom rule group ARN
// (…:rulegroup/<name>/<id>) becomes its name.
func groupName(id string) string {
	if i := strings.LastIndex(id, "#"); i >= 0 {
		return id[i+1:]
	}
	if i := strings.Index(id, "rulegroup/"); i >= 0 {
		rest := id[i+len("rulegroup/"):]
		if j := strings.Index(rest, "/"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return id
}

// exploitGroups and exploitLabels mark COUNT matches from the managed rule
// groups that detect injection and known exploit payloads.
var (
	exploitGroups = []string{"AWSManagedRulesSQLiRuleSet/", "AWSManagedRulesKnownBadInputsRuleSet/", "AWSManagedRulesCommonRuleSet/"}
	exploitLabels = []string{"awswaf:managed:aws:sql-database:", "awswaf:managed:aws:known-bad-inputs:", "awswaf:managed:aws:core-rule-set:"}
)

// ExploitMatch returns the COUNT rule or label that shows an allowed
// request carried an exploit payload, or "" when the request was not
// allowed or matched nothing of that kind.
func (e Entry) ExploitMatch() string {
	if e.Action != "ALLOW" {
		return ""
	}
	for _, r := range e.CountRules {
		for _, g := range exploitGroups {
			if strings.HasPrefix(r, g) {
				return r
			}
		}
	}
	for _, l := range e.Labels {
		for _, p := range exploitLabels {
			if strings.HasPrefix(l, p) {
				return l
			}
		}
	}
	return ""
}

// IsLogKey reports whether a listed key is a WAF log object.
func IsLogKey(key string) bool {
	return strings.HasSuffix(key, ".log.gz") || strings.HasSuffix(key, ".gz")
}

// maxLine bounds one JSON record. WAF records with many headers stay well
// below this.
const maxLine = 1 << 20

// LineError reports lines of an object that could not be parsed. Decode
// returns it alongside every entry that did parse.
type LineError struct {
	Bad   int
	First error
}

func (e *LineError) Error() string {
	return fmt.Sprintf("%d unparseable lines, first: %v", e.Bad, e.First)
}

// Decode reads one log object, gzipped or plain, and parses every line.
// Unparseable lines are skipped and reported through a *LineError; I/O and
// gzip errors return no entries.
func Decode(_ string, r io.Reader) ([]Entry, error) {
	br := bufio.NewReader(r)
	var src io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		src = zr
	}
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	var out []Entry
	var lineErr *LineError
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		e, err := Parse(line)
		if err != nil {
			if lineErr == nil {
				lineErr = &LineError{First: err}
			}
			lineErr.Bad++
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if lineErr != nil {
		return out, lineErr
	}
	return out, nil
}
