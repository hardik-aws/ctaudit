package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/gsmappdev/ctaudit/internal/ctevent"
	"github.com/gsmappdev/ctaudit/internal/elblog"
	"github.com/gsmappdev/ctaudit/internal/query"
	"github.com/gsmappdev/ctaudit/internal/s3src"
)

// emitCounter hands each fetch worker its own counter. The counters are
// written without locks, so the race detector fails the test if a writer is
// ever shared between goroutines.
type emitCounter struct {
	mu     sync.Mutex
	counts []*int
}

func (c *emitCounter) new() *int {
	n := new(int)
	c.mu.Lock()
	c.counts = append(c.counts, n)
	c.mu.Unlock()
	return n
}

func (c *emitCounter) total() (writers, emitted int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.counts {
		emitted += *n
	}
	return len(c.counts), emitted
}

func TestRunEmitsEveryMatchPastMaxEvents(t *testing.T) {
	objects := map[string][]byte{}
	for i := 0; i < 20; i++ {
		objects[key(fmt.Sprintf("o%02d", i))] = objectWith(t, "DeleteBucket", "arn:aws:iam::1:user/alice", "", "14")
	}
	objects[key("bob")] = objectWith(t, "DeleteBucket", "arn:aws:iam::1:user/bob", "", "14")

	var c emitCounter
	res, err := Run(context.Background(), s3src.NewMemStore(objects), Options{
		Scope:        testScope(),
		Filter:       query.Filter{Principal: "alice"},
		MaxEvents:    5,
		FetchWorkers: 4,
		Emit: func() func(ctevent.Record) {
			n := c.new()
			return func(ctevent.Record) { *n++ }
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	writers, emitted := c.total()
	if emitted != 20 || res.MatchedRecords != 20 {
		t.Errorf("emitted %d, matched %d, want 20 each (filtered records must not be emitted)", emitted, res.MatchedRecords)
	}
	if writers < 1 || writers > 4 {
		t.Errorf("Emit called %d times, want once per fetch worker (1..4)", writers)
	}
	if len(res.Matches) != 5 {
		t.Errorf("kept %d matches, want MaxEvents=5", len(res.Matches))
	}
}

func TestRunELBEmitsRequestsAndConns(t *testing.T) {
	const lb = "app/k8s-web-0123456789/0123456789abcdef 192.0.2.57"
	conns := strings.Join([]string{
		`2026-09-23T07:11:27.691358Z 198.18.71.40 64326 443 TLSv1.2 ECDHE-ECDSA-AES128-GCM-SHA256 0.337 "-" - - Success TID_1 secp256r1 ` + lb,
		`2026-09-23T07:11:32.882572Z 198.51.100.159 61814 80 - - - "-" - - - TID_2 - ` + lb,
	}, "\n") + "\n"
	objs := map[string][]byte{
		elbTestPrefix + "conn_log_111122223333_elasticloadbalancing_us-east-1_app.k8s-web-0123456789.0123456789abcdef_20260923T0715Z_192.0.2.66_57hw2gm1.log.gz": gz(t, conns),
	}
	for i := 0; i < 6; i++ {
		ts := fmt.Sprintf("2026-09-23T%02d:00:00.000000Z", 10-i)
		objs[elbKey("app.tiles.98e3", fmt.Sprintf("%d.log.gz", i))] = gz(t, albLine(ts, "1.1.1.1", "200", "/", 0.001))
	}

	var mu sync.Mutex
	var reqs, cns int
	res, err := RunELB(context.Background(), s3src.NewMemStore(objs), ELBOptions{
		Scope:        elbScope(),
		MaxEvents:    1,
		FetchWorkers: 3,
		Emit: func() func(elblog.Entry) {
			return func(e elblog.Entry) {
				mu.Lock()
				defer mu.Unlock()
				if e.Conn {
					cns++
				} else {
					reqs++
				}
			}
		},
	})
	if err != nil {
		t.Fatalf("RunELB: %v", err)
	}
	if reqs != 6 || cns != 2 {
		t.Errorf("emitted %d requests and %d conns, want 6 and 2", reqs, cns)
	}
	if len(res.Matches) != 1 || len(res.ConnMatches) != 1 {
		t.Errorf("kept %d requests and %d conns, want MaxEvents=1 each", len(res.Matches), len(res.ConnMatches))
	}
}
