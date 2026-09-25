package sink

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	j, err := NewJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := j.NewWriter()
			for n := range 250 {
				b, _ := json.Marshal(map[string]int{"w": i, "n": n})
				w.Write(Labels{"k": "v"}, time.Time{}, b)
			}
		}()
	}
	wg.Wait()
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	lines := 0
	for sc.Scan() {
		var v map[string]int
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatalf("line %d is not JSON: %q", lines+1, sc.Text())
		}
		lines++
	}
	if lines != 1000 {
		t.Errorf("got %d lines, want 1000", lines)
	}
}

func TestNewJSONLBadPath(t *testing.T) {
	if _, err := NewJSONL(filepath.Join(t.TempDir(), "missing", "x.jsonl")); err == nil {
		t.Error("NewJSONL in a missing directory = nil, want an error")
	}
}
