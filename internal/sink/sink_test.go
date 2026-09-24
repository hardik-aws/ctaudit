package sink

import (
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestAuthFromEnv(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    Auth
		wantErr string
	}{
		{name: "none", env: nil, want: Auth{}},
		{name: "basic", env: map[string]string{"X_USER": "u", "X_PASSWORD": "p"}, want: Auth{User: "u", Password: "p"}},
		{name: "user only", env: map[string]string{"X_USER": "u"}, want: Auth{User: "u"}},
		{name: "token", env: map[string]string{"X_TOKEN": "t"}, want: Auth{Token: "t"}},
		{name: "token and user", env: map[string]string{"X_TOKEN": "t", "X_USER": "u"}, wantErr: "not both"},
		{name: "password without user", env: map[string]string{"X_PASSWORD": "p"}, wantErr: "X_USER is not"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AuthFromEnv("X", envMap(tt.env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCheckURL(t *testing.T) {
	for _, ok := range []string{"http://loki:3100", "https://loki.example.com/", "http://10.0.0.1:9091"} {
		if err := CheckURL(ok); err != nil {
			t.Errorf("CheckURL(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "loki:3100", "ftp://x", "http://", "://x"} {
		if err := CheckURL(bad); err == nil {
			t.Errorf("CheckURL(%q) = nil, want an error", bad)
		}
	}
}

type recWriter struct{ lines *[]string }

func (w recWriter) Write(_ Labels, line []byte) { *w.lines = append(*w.lines, string(line)) }

type recSink struct {
	lines []string
	err   error
}

func (s *recSink) NewWriter() Writer { return recWriter{&s.lines} }
func (s *recSink) Close() error      { return s.err }

func TestMulti(t *testing.T) {
	a, b := &recSink{}, &recSink{}
	m := Multi(a, b)
	m.NewWriter().Write(Labels{"k": "v"}, []byte("x"))
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(a.lines) != 1 || len(b.lines) != 1 {
		t.Errorf("a=%v b=%v, want one line each", a.lines, b.lines)
	}

	b.err = errString("boom")
	if err := Multi(a, b).Close(); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("Close = %v, want boom", err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestLabelsKeyIsOrderIndependent(t *testing.T) {
	a := Labels{"job": "ctaudit", "kind": "event"}
	b := Labels{"kind": "event", "job": "ctaudit"}
	if a.key() != b.key() {
		t.Error("equal label sets have different keys")
	}
	if a.key() == (Labels{"job": "ctaudit", "kind": "finding"}).key() {
		t.Error("different label sets have the same key")
	}
}
