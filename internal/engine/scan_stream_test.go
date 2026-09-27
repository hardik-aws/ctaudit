package engine

import (
	"bufio"
	"context"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

type sumShard struct{ sum int }

func TestScanStream(t *testing.T) {
	store := s3src.NewMemStore(map[string][]byte{
		"p/a.txt": []byte("1\n2\n3\n"),
		"p/b.txt": []byte("4\nbad\n5\n"),
		"p/c.txt": []byte("bad\n"),
	})
	out, err := scan(context.Background(), store, scanSpec[int, *sumShard]{
		prefixes:     []string{"p/"},
		fetchWorkers: 1,
		keep:         func(k string) bool { return strings.HasSuffix(k, ".txt") },
		stream: func(_ string, r io.Reader, emit func(int)) error {
			sc := bufio.NewScanner(r)
			for sc.Scan() {
				n, err := strconv.Atoi(sc.Text())
				if err != nil {
					return errors.New("bad line")
				}
				emit(n)
			}
			return sc.Err()
		},
		decode: func(string, io.Reader) ([]int, error) {
			t.Fatal("decode must not run when stream is set")
			return nil, nil
		},
		newShard: func() *sumShard { return &sumShard{} },
		visit:    func(sh *sumShard, n int) bool { sh.sum += n; return n%2 == 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.shards[0].sum != 10 || out.recordsRead != 4 || out.objectsScanned != 2 {
		t.Fatalf("sum %d records %d objects %d", out.shards[0].sum, out.recordsRead, out.objectsScanned)
	}
	if !reflect.DeepEqual(out.readKeys, []string{"p/a.txt", "p/b.txt"}) {
		t.Fatalf("readKeys %v", out.readKeys)
	}
	if len(out.errs) != 2 || !strings.Contains(strings.Join(out.errs, "\n"), "decode p/c.txt: bad line") {
		t.Fatalf("errs %v", out.errs)
	}
}
