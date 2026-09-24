package sink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// statusError is a non-success HTTP response.
type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("HTTP %d", e.code)
	}
	return fmt.Sprintf("HTTP %d: %s", e.code, e.body)
}

// retryable reports whether err is worth another attempt: a network error,
// 429, or any 5xx. Other 4xx responses mean the request itself is wrong.
func retryable(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.code == http.StatusTooManyRequests || se.code >= 500
	}
	return true
}

// post sends body to url, retrying up to attempts times with exponential
// backoff from backoff. prepare sets the headers on each fresh request.
//
// log, when set, gets one debug line per attempt with attrs added. The line
// carries the URL without credentials, never the headers or body.
func post(ctx context.Context, client *http.Client, url string, body []byte, attempts int, backoff time.Duration, prepare func(*http.Request), log *slog.Logger, attrs ...any) error {
	if attempts < 1 {
		attempts = 1
	}
	target := redactURL(url)
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w (last error: %v)", ctx.Err(), err)
			case <-time.After(backoff << (i - 1)):
			}
		}
		started := time.Now()
		err = postOnce(ctx, client, url, body, prepare)
		if log != nil {
			line := append([]any{"url", target, "attempt", i + 1, "bytes", len(body), "dur", time.Since(started)}, attrs...)
			if err != nil {
				line = append(line, "err", err, "retry", retryable(err) && i+1 < attempts)
			}
			log.Debug("http post", line...)
		}
		if err == nil || !retryable(err) {
			return err
		}
	}
	return err
}

func postOnce(ctx context.Context, client *http.Client, url string, body []byte, prepare func(*http.Request)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	prepare(req)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		return &statusError{code: resp.StatusCode, body: string(bytes.TrimSpace(msg))}
	}
	return nil
}

// redactURL drops any user info from raw so it is safe to log.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable URL)"
	}
	return u.Redacted()
}
