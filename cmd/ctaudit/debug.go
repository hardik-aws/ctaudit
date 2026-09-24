package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

// logFlags turn on debug logging to stderr. Debug lines carry keys, counts,
// timings, and errors, never credentials, headers, or record contents.
type logFlags struct {
	debug  bool
	format string
}

func (l *logFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&l.debug, "debug", false, "log each step of the scan to stderr (also CTAUDIT_DEBUG=1)")
	fs.StringVar(&l.format, "log-format", "text", "debug log format: text or json")
}

// resolve validates --log-format and applies CTAUDIT_DEBUG when --debug is
// not set.
func (l *logFlags) resolve() error {
	l.format = strings.ToLower(strings.TrimSpace(l.format))
	if l.format != "text" && l.format != "json" {
		return fmt.Errorf("--log-format: want text or json, got %q", l.format)
	}
	if !l.debug {
		if v := strings.TrimSpace(getenv("CTAUDIT_DEBUG")); v != "" {
			on, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("CTAUDIT_DEBUG: want a boolean such as 1 or true, got %q", v)
			}
			l.debug = on
		}
	}
	return nil
}

// logger returns a debug logger writing to w, or nil when debug is off.
func (l logFlags) logger(w io.Writer) *slog.Logger {
	if !l.debug {
		return nil
	}
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	if l.format == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// debugLog logs msg when log is set.
func debugLog(log *slog.Logger, msg string, args ...any) {
	if log != nil {
		log.Debug(msg, args...)
	}
}

// debugScope logs what a scan will read before it starts.
func debugScope(log *slog.Logger, sub string, store storeConfig, scope s3src.Scope, since, until time.Time, listWorkers, fetchWorkers int) {
	if log == nil {
		return
	}
	prefixes := scope.Prefixes()
	log.Debug("scan scope", "subcommand", sub, "bucket", store.Bucket, "bucket_region", store.BucketRegion,
		"accounts", strings.Join(scope.Accounts, ","), "regions", strings.Join(scope.Regions, ","),
		"scope_start", scope.Start.Format(dayLayout), "scope_end", scope.End.Format(dayLayout),
		"since", since, "until", until, "prefixes", len(prefixes),
		"list_workers", listWorkers, "fetch_workers", fetchWorkers)
}
