package stats

import (
	"sort"
	"strconv"
	"time"

	"github.com/gsmappdev/ctaudit/internal/s3log"
)

const (
	// S3Other collects the counts of keys past S3MaxKeys in a capped
	// counter. Findings rules ignore it.
	S3Other = "(other)"
	// S3MaxKeys caps the distinct keys of every open-ended S3 counter, so
	// a busy public bucket seen by millions of clients cannot exhaust
	// memory.
	S3MaxKeys = 50000
	// s3MaxAccessChanges caps the access changes kept for findings.
	s3MaxAccessChanges = 1000
)

// S3AnonHit records successful anonymous requests of one kind to one
// source bucket.
type S3AnonHit struct {
	Count int
	First time.Time
	IPs   Counter
	Keys  Counter
	Ops   Counter
}

func newS3AnonHit() *S3AnonHit {
	return &S3AnonHit{IPs: Counter{}, Keys: Counter{}, Ops: Counter{}}
}

// S3AccessChange is one successful bucket policy, ACL, or public access
// block change.
type S3AccessChange struct {
	Time      time.Time
	Bucket    string
	Operation string
	Key       string
	Principal string
	RemoteIP  string
}

// S3Summary holds every aggregate the S3 report and findings need. One
// goroutine owns it during a scan; shards are merged after.
type S3Summary struct {
	Total       int
	First, Last time.Time
	BytesSent   int64
	Errors      int
	Anonymous   int
	Denied      int

	ByOperation  Counter
	ByStatus     Counter
	ByErrorCode  Counter
	ByBucket     Counter
	ByTLS        Counter
	ByAuthType   Counter
	BySigVersion Counter

	// Open-ended counters, capped at S3MaxKeys. ByKey is keyed by
	// "bucket/key".
	ByRequester Counter
	ByRemoteIP  Counter
	ByKey       Counter
	ByUserAgent Counter

	// ByHour is keyed by Unix hour; each value counts status classes.
	ByHour map[int64]Counter

	// Rule inputs, capped at S3MaxKeys. Requester-keyed ones leave out
	// anonymous requests, which the IP-keyed ones cover.
	DeniedByIP         Counter
	DeniedByRequester  Counter
	DeletesByPrincipal Counter
	BytesByRequester   Counter
	BytesByIP          Counter
	AnonWrites         map[string]*S3AnonHit
	AnonReads          map[string]*S3AnonHit
	AccessChanges      []S3AccessChange
	WeakTLSBy          Counter
	PlainHTTPBy        Counter
	SigV2By            Counter
}

// NewS3Summary returns an S3Summary with every map initialised.
func NewS3Summary() *S3Summary {
	return &S3Summary{
		ByOperation: Counter{}, ByStatus: Counter{}, ByErrorCode: Counter{}, ByBucket: Counter{},
		ByTLS: Counter{}, ByAuthType: Counter{}, BySigVersion: Counter{},
		ByRequester: Counter{}, ByRemoteIP: Counter{}, ByKey: Counter{}, ByUserAgent: Counter{},
		ByHour:     map[int64]Counter{},
		DeniedByIP: Counter{}, DeniedByRequester: Counter{}, DeletesByPrincipal: Counter{},
		BytesByRequester: Counter{}, BytesByIP: Counter{},
		AnonWrites: map[string]*S3AnonHit{}, AnonReads: map[string]*S3AnonHit{},
		WeakTLSBy: Counter{}, PlainHTTPBy: Counter{}, SigV2By: Counter{},
	}
}

// capAdd adds n to key, or to S3Other once the counter holds S3MaxKeys
// distinct keys and key is new.
func capAdd(c Counter, key string, n int) {
	if key == "" || n == 0 {
		return
	}
	if _, ok := c[key]; ok || len(c) < S3MaxKeys {
		c[key] += n
		return
	}
	c[S3Other] += n
}

func capMerge(dst, src Counter) {
	for k, v := range src {
		capAdd(dst, k, v)
	}
}

func anonHit(m map[string]*S3AnonHit, e s3log.Entry) {
	h := m[e.Bucket]
	if h == nil {
		h = newS3AnonHit()
		m[e.Bucket] = h
	}
	h.Count++
	if h.First.IsZero() || (!e.Time.IsZero() && e.Time.Before(h.First)) {
		h.First = e.Time
	}
	capAdd(h.IPs, e.RemoteIP, 1)
	capAdd(h.Keys, e.Key, 1)
	h.Ops.add(e.Operation)
}

// earliestChanges sorts changes by time and keeps at most n.
func earliestChanges(c []S3AccessChange, n int) []S3AccessChange {
	sort.SliceStable(c, func(i, j int) bool { return c[i].Time.Before(c[j].Time) })
	if len(c) > n {
		c = c[:n]
	}
	return c
}

// Add folds one entry into the summary.
func (s *S3Summary) Add(e s3log.Entry) {
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
		s.ByHour[h].add(e.StatusClass())
	}
	principal := e.Principal()
	anon := e.Requester == ""
	s.BytesSent += e.BytesSent
	if e.IsError() {
		s.Errors++
	}
	if anon {
		s.Anonymous++
	}

	s.ByOperation.add(e.Operation)
	if e.Status > 0 {
		s.ByStatus.add(strconv.Itoa(e.Status))
	}
	s.ByErrorCode.add(e.ErrorCode)
	s.ByBucket.add(e.Bucket)
	s.ByTLS.add(e.TLSVersion)
	s.ByAuthType.add(e.AuthType)
	s.BySigVersion.add(e.SigVersion)
	capAdd(s.ByRequester, principal, 1)
	capAdd(s.ByRemoteIP, e.RemoteIP, 1)
	if e.Key != "" {
		capAdd(s.ByKey, e.Bucket+"/"+e.Key, 1)
	}
	capAdd(s.ByUserAgent, e.UserAgent, 1)

	if e.BytesSent > 0 {
		capAdd(s.BytesByIP, e.RemoteIP, int(e.BytesSent))
		if !anon {
			capAdd(s.BytesByRequester, principal, int(e.BytesSent))
		}
	}
	if e.Denied() {
		s.Denied++
		capAdd(s.DeniedByIP, e.RemoteIP, 1)
		if !anon {
			capAdd(s.DeniedByRequester, principal, 1)
		}
	}
	ok := e.Success()
	if ok && e.IsObjectDelete() {
		capAdd(s.DeletesByPrincipal, principal, 1)
	}
	if ok && anon {
		switch {
		case e.IsObjectWrite() || e.IsObjectDelete() || e.IsMultiDelete():
			anonHit(s.AnonWrites, e)
		case e.IsObjectRead():
			anonHit(s.AnonReads, e)
		}
	}
	if ok && e.IsAccessChange() {
		s.AccessChanges = append(s.AccessChanges, S3AccessChange{
			Time: e.Time, Bucket: e.Bucket, Operation: e.Operation, Key: e.Key, Principal: principal, RemoteIP: e.RemoteIP,
		})
		// Trimming at 2x amortises the sort.
		if len(s.AccessChanges) >= 2*s3MaxAccessChanges {
			s.AccessChanges = earliestChanges(s.AccessChanges, s3MaxAccessChanges)
		}
	}
	if e.WeakTLS() {
		capAdd(s.WeakTLSBy, principal, 1)
	}
	if e.PlainHTTP {
		capAdd(s.PlainHTTPBy, principal, 1)
	}
	if e.SigV2() {
		capAdd(s.SigV2By, principal, 1)
	}
}

// Merge folds another summary into this one.
func (s *S3Summary) Merge(o *S3Summary) {
	if o == nil {
		return
	}
	s.Total += o.Total
	s.BytesSent += o.BytesSent
	s.Errors += o.Errors
	s.Anonymous += o.Anonymous
	s.Denied += o.Denied
	if !o.First.IsZero() && (s.First.IsZero() || o.First.Before(s.First)) {
		s.First = o.First
	}
	if o.Last.After(s.Last) {
		s.Last = o.Last
	}
	for _, p := range [][2]Counter{
		{s.ByOperation, o.ByOperation}, {s.ByStatus, o.ByStatus}, {s.ByErrorCode, o.ByErrorCode},
		{s.ByBucket, o.ByBucket}, {s.ByTLS, o.ByTLS}, {s.ByAuthType, o.ByAuthType}, {s.BySigVersion, o.BySigVersion},
	} {
		p[0].merge(p[1])
	}
	for _, p := range [][2]Counter{
		{s.ByRequester, o.ByRequester}, {s.ByRemoteIP, o.ByRemoteIP}, {s.ByKey, o.ByKey}, {s.ByUserAgent, o.ByUserAgent},
		{s.DeniedByIP, o.DeniedByIP}, {s.DeniedByRequester, o.DeniedByRequester}, {s.DeletesByPrincipal, o.DeletesByPrincipal},
		{s.BytesByRequester, o.BytesByRequester}, {s.BytesByIP, o.BytesByIP},
		{s.WeakTLSBy, o.WeakTLSBy}, {s.PlainHTTPBy, o.PlainHTTPBy}, {s.SigV2By, o.SigV2By},
	} {
		capMerge(p[0], p[1])
	}
	for h, c := range o.ByHour {
		if s.ByHour[h] == nil {
			s.ByHour[h] = Counter{}
		}
		s.ByHour[h].merge(c)
	}
	for _, p := range [][2]map[string]*S3AnonHit{{s.AnonWrites, o.AnonWrites}, {s.AnonReads, o.AnonReads}} {
		for bucket, h := range p[1] {
			d := p[0][bucket]
			if d == nil {
				d = newS3AnonHit()
				p[0][bucket] = d
			}
			d.Count += h.Count
			if d.First.IsZero() || (!h.First.IsZero() && h.First.Before(d.First)) {
				d.First = h.First
			}
			capMerge(d.IPs, h.IPs)
			capMerge(d.Keys, h.Keys)
			d.Ops.merge(h.Ops)
		}
	}
	s.AccessChanges = earliestChanges(append(s.AccessChanges, o.AccessChanges...), s3MaxAccessChanges)
}
