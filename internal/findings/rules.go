// Package findings applies security rules to CloudTrail records. Rules are
// pure functions over a single record, so a Detector can run on a per-worker
// shard and be merged at the end of a scan.
package findings

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
)

// Severity ranks a finding's urgency.
type Severity int

// Severity levels, ordered so that higher is more urgent.
const (
	SevLow Severity = iota
	SevMedium
	SevHigh
	SevCritical
)

// String renders the severity for reports.
func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// ParseSeverity converts a flag value such as "high" into a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW":
		return SevLow, nil
	case "MEDIUM":
		return SevMedium, nil
	case "HIGH":
		return SevHigh, nil
	case "CRITICAL":
		return SevCritical, nil
	default:
		return SevLow, fmt.Errorf("unknown severity %q (want low, medium, high, or critical)", s)
	}
}

// Finding is one rule hit against one record.
type Finding struct {
	Rule     string
	Severity Severity
	Title    string
	Actor    string
	Account  string
	Region   string
	EventID  string
	Detail   string
	Time     time.Time
}

// Rule inspects a single record and reports a Finding when it matches.
type Rule interface {
	ID() string
	Check(r ctevent.Record) (Finding, bool)
}

// Detector runs a rule set over records and collects the hits.
type Detector struct {
	rules []Rule
	found []Finding
	// Max caps how many findings are retained. Zero means the default cap.
	Max int
	// Dropped counts findings discarded because the cap was reached.
	Dropped int
	// MaxSeverity is the highest severity of every rule hit this detector has
	// seen, including hits that were discarded because the cap was full.
	MaxSeverity Severity
	// Seen is true once any hit has been observed, so that MaxSeverity's zero
	// value (SevLow) can be told apart from "no hits at all".
	Seen bool
	// Counts is the number of rule hits per severity, including hits that
	// were discarded because the cap was full. It is nil until the first hit.
	Counts map[Severity]int

	// minCached and minSev cache the lowest severity among currently retained
	// findings, so a steady stream of low-severity hits after the cap fills
	// can be rejected without rescanning found on every hit. minIdx is the
	// index of that cached minimum, used to replace it in place. The cache is
	// invalidated (minCached = false) whenever found changes in a way that
	// could change the minimum.
	minCached bool
	minSev    Severity
	minIdx    int
}

// defaultMaxFindings keeps a pathological scan from exhausting memory.
const defaultMaxFindings = 5000

// NewDetector builds a Detector over the given rules.
func NewDetector(rules []Rule) *Detector {
	return &Detector{rules: rules}
}

func (d *Detector) cap() int {
	if d.Max > 0 {
		return d.Max
	}
	return defaultMaxFindings
}

// Inspect runs every rule against one record.
func (d *Detector) Inspect(r ctevent.Record) {
	for _, rule := range d.rules {
		f, ok := rule.Check(r)
		if !ok {
			continue
		}
		d.keep(f)
	}
}

// Merge folds another detector's findings into this one. other may have
// discarded hits of its own (tracked only in its MaxSeverity/Seen, not in its
// found slice), so those are folded in directly rather than rediscovered by
// replaying other.found.
func (d *Detector) Merge(other *Detector) {
	if other == nil {
		return
	}
	if other.Seen {
		d.observe(other.MaxSeverity)
	}
	d.Dropped += other.Dropped
	for sev, n := range other.Counts {
		d.count(sev, n)
	}
	for _, f := range other.found {
		d.retain(f)
	}
}

// keep records a hit's severity and then decides whether to retain it. It is
// the shared entry point Inspect uses for freshly observed hits.
func (d *Detector) keep(f Finding) {
	d.observe(f.Severity)
	d.count(f.Severity, 1)
	d.retain(f)
}

// count adds n hits of severity sev to Counts.
func (d *Detector) count(sev Severity, n int) {
	if d.Counts == nil {
		d.Counts = map[Severity]int{}
	}
	d.Counts[sev] += n
}

// observe folds sev into MaxSeverity, regardless of whether the hit that
// carried it ends up retained.
func (d *Detector) observe(sev Severity) {
	if !d.Seen || sev > d.MaxSeverity {
		d.MaxSeverity = sev
	}
	d.Seen = true
}

// retain applies the cap: while there is room, f is appended outright; once
// full, f replaces the lowest-severity retained finding if f outranks it,
// and is otherwise dropped. Either way, a finding not ending up in found
// counts against Dropped exactly once.
func (d *Detector) retain(f Finding) {
	if len(d.found) < d.cap() {
		d.found = append(d.found, f)
		d.minCached = false
		return
	}

	// Cheap rejection using the cached minimum before scanning for it.
	if d.minCached && f.Severity <= d.minSev {
		d.Dropped++
		return
	}

	minSev, minIdx := d.lowestRetained()
	if f.Severity <= minSev {
		d.minSev, d.minIdx, d.minCached = minSev, minIdx, true
		d.Dropped++
		return
	}
	d.found[minIdx] = f
	d.Dropped++
	d.minCached = false
}

// lowestRetained scans found for the lowest-severity entry. It is only
// called when the cap is full and the cached minimum is unusable or absent.
func (d *Detector) lowestRetained() (Severity, int) {
	minIdx := 0
	minSev := d.found[0].Severity
	for i := 1; i < len(d.found); i++ {
		if d.found[i].Severity < minSev {
			minSev = d.found[i].Severity
			minIdx = i
		}
	}
	return minSev, minIdx
}

// Findings returns the collected findings, most severe first and, within a
// severity, oldest first.
func (d *Detector) Findings() []Finding {
	out := make([]Finding, len(d.found))
	copy(out, d.found)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Time.Before(out[j].Time)
	})
	return out
}

// funcRule adapts a plain function into a Rule, so that adding a rule means
// writing one closure rather than one type.
type funcRule struct {
	id    string
	check func(r ctevent.Record) (Finding, bool)
}

func (f funcRule) ID() string { return f.id }

func (f funcRule) Check(r ctevent.Record) (Finding, bool) { return f.check(r) }

// newFinding fills in the fields every finding shares.
func newFinding(id string, sev Severity, title, detail string, r ctevent.Record) Finding {
	return Finding{
		Rule:     id,
		Severity: sev,
		Title:    title,
		Actor:    r.Actor(),
		Account:  r.RecipientAccountID,
		Region:   r.AWSRegion,
		EventID:  r.EventID,
		Detail:   detail,
		Time:     r.EventTime,
	}
}

// rawField pulls a single string field out of a raw JSON object without
// decoding the whole document into a map for every record.
func rawField(raw json.RawMessage, field string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	v, ok := m[field]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return ""
	}
	return s
}

func isOneOf(value string, options ...string) bool {
	for _, o := range options {
		if value == o {
			return true
		}
	}
	return false
}

// iamMutationPrefixes are the verbs that change IAM state.
var iamMutationPrefixes = []string{"Create", "Delete", "Put", "Update", "Attach", "Detach", "Add", "Remove", "Set", "Tag", "Untag", "Change", "Enable", "Disable", "Upload"}

// DefaultRules returns the built-in security rule set.
func DefaultRules() []Rule {
	return []Rule{
		funcRule{id: "root-usage", check: func(r ctevent.Record) (Finding, bool) {
			if r.UserIdentity.Type != "Root" {
				return Finding{}, false
			}
			// AWS itself emits a few Root-typed service events; the ones that
			// matter are the ones a human could have made.
			if r.UserIdentity.InvokedBy != "" {
				return Finding{}, false
			}
			detail := fmt.Sprintf("Root account used for %s in %s", r.EventName, r.AWSRegion)
			return newFinding("root-usage", SevCritical, "Root account activity", detail, r), true
		}},

		funcRule{id: "console-no-mfa", check: func(r ctevent.Record) (Finding, bool) {
			if r.EventName != "ConsoleLogin" {
				return Finding{}, false
			}
			if rawField(r.ResponseElements, "ConsoleLogin") != "Success" {
				return Finding{}, false
			}
			if rawField(r.AdditionalEventData, "MFAUsed") != "No" {
				return Finding{}, false
			}
			detail := fmt.Sprintf("ConsoleLogin succeeded without MFA from %s", r.SourceIPAddress)
			return newFinding("console-no-mfa", SevHigh, "Console login without MFA", detail, r), true
		}},

		funcRule{id: "console-login-failed", check: func(r ctevent.Record) (Finding, bool) {
			if r.EventName != "ConsoleLogin" {
				return Finding{}, false
			}
			if rawField(r.ResponseElements, "ConsoleLogin") != "Failure" {
				return Finding{}, false
			}
			detail := fmt.Sprintf("Failed console login from %s", r.SourceIPAddress)
			return newFinding("console-login-failed", SevMedium, "Failed console login", detail, r), true
		}},

		funcRule{id: "access-denied", check: func(r ctevent.Record) (Finding, bool) {
			if !isOneOf(r.ErrorCode, "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "Client.UnauthorizedOperation") {
				return Finding{}, false
			}
			detail := fmt.Sprintf("%s denied on %s (%s)", r.ErrorCode, r.EventName, r.ServiceName())
			return newFinding("access-denied", SevLow, "Authorization failure", detail, r), true
		}},

		funcRule{id: "iam-mutation", check: func(r ctevent.Record) (Finding, bool) {
			if r.ServiceName() != "iam" {
				return Finding{}, false
			}
			mutating := false
			for _, p := range iamMutationPrefixes {
				if strings.HasPrefix(r.EventName, p) {
					mutating = true
					break
				}
			}
			if !mutating {
				return Finding{}, false
			}
			detail := fmt.Sprintf("%s in %s", r.EventName, r.AWSRegion)
			return newFinding("iam-mutation", SevMedium, "IAM configuration changed", detail, r), true
		}},

		funcRule{id: "access-key-created", check: func(r ctevent.Record) (Finding, bool) {
			if r.ServiceName() != "iam" || r.EventName != "CreateAccessKey" {
				return Finding{}, false
			}
			target := rawField(r.RequestParameters, "userName")
			if target == "" {
				target = "the calling identity"
			}
			detail := fmt.Sprintf("Long-lived access key created for %s", target)
			return newFinding("access-key-created", SevHigh, "Access key created", detail, r), true
		}},

		funcRule{id: "cloudtrail-tamper", check: func(r ctevent.Record) (Finding, bool) {
			if r.ServiceName() != "cloudtrail" {
				return Finding{}, false
			}
			if !isOneOf(r.EventName, "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteEventDataStore") {
				return Finding{}, false
			}
			name := rawField(r.RequestParameters, "name")
			detail := strings.TrimSpace(fmt.Sprintf("%s on trail %s", r.EventName, name))
			return newFinding("cloudtrail-tamper", SevCritical, "CloudTrail configuration changed", detail, r), true
		}},

		funcRule{id: "s3-exposure", check: func(r ctevent.Record) (Finding, bool) {
			if r.ServiceName() != "s3" {
				return Finding{}, false
			}
			if !isOneOf(r.EventName, "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl", "PutBucketPublicAccessBlock", "DeletePublicAccessBlock", "PutAccountPublicAccessBlock") {
				return Finding{}, false
			}
			bucket := rawField(r.RequestParameters, "bucketName")
			detail := strings.TrimSpace(fmt.Sprintf("%s on bucket %s", r.EventName, bucket))
			return newFinding("s3-exposure", SevHigh, "S3 bucket exposure setting changed", detail, r), true
		}},

		funcRule{id: "sg-open-ingress", check: func(r ctevent.Record) (Finding, bool) {
			if r.ServiceName() != "ec2" || r.EventName != "AuthorizeSecurityGroupIngress" {
				return Finding{}, false
			}
			// The ipPermissions shape varies by API version, so check the raw
			// parameters for an open CIDR rather than modelling every variant.
			params := string(r.RequestParameters)
			if !strings.Contains(params, "0.0.0.0/0") && !strings.Contains(params, "::/0") {
				return Finding{}, false
			}
			return newFinding("sg-open-ingress", SevHigh, "Security group opened to the internet",
				"AuthorizeSecurityGroupIngress with 0.0.0.0/0", r), true
		}},

		funcRule{id: "kms-destruction", check: func(r ctevent.Record) (Finding, bool) {
			if r.ServiceName() != "kms" {
				return Finding{}, false
			}
			if !isOneOf(r.EventName, "DisableKey", "ScheduleKeyDeletion", "DeleteAlias", "DisableKeyRotation") {
				return Finding{}, false
			}
			keyID := rawField(r.RequestParameters, "keyId")
			detail := strings.TrimSpace(fmt.Sprintf("%s on key %s", r.EventName, keyID))
			return newFinding("kms-destruction", SevHigh, "KMS key availability reduced", detail, r), true
		}},
	}
}
