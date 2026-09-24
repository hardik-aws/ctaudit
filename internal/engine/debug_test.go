package engine

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

func TestRunDebugLogsPrefixesAndObjects(t *testing.T) {
	good, bad, seen := key("good"), key("bad"), key("seen")
	store := s3src.NewMemStore(map[string][]byte{
		good: objectWith(t, "DeleteBucket", "arn:aws:iam::1:user/alice", "", "10"),
		bad:  []byte("this is not gzip"),
		seen: objectWith(t, "PutObject", "arn:aws:iam::1:user/bob", "", "11"),
	})
	var buf bytes.Buffer
	_, err := Run(context.Background(), store, Options{
		Scope: testScope(),
		Skip:  func(k string) bool { return k == seen },
		Debug: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`msg="listed prefix"`,
		"skipped_seen=1",
		`msg="object read" key=` + good,
		"records=1 matched=1",
		`msg="object failed" key=` + bad,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("debug output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "key="+seen) {
		t.Errorf("skipped key logged as fetched:\n%s", out)
	}
}

func TestRunNoDebugLogger(t *testing.T) {
	store := s3src.NewMemStore(map[string][]byte{key("a"): objectWith(t, "PutObject", "arn:aws:iam::1:user/a", "", "10")})
	if _, err := Run(context.Background(), store, Options{Scope: testScope()}); err != nil {
		t.Fatalf("Run without Debug: %v", err)
	}
}
