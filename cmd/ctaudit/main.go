// Command ctaudit scans AWS logs straight from S3. The cloudtrail subcommand
// reports security findings, forensic matches, and API volume statistics for
// CloudTrail logs; the elb subcommand reports traffic statistics and forensic
// matches for Elastic Load Balancing access logs. It needs only s3:ListBucket
// and s3:GetObject on the log bucket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/gsmappdev/ctaudit/internal/s3src"
)

// Exit codes. See the README.
const (
	exitOK       = 0
	exitFindings = 1
	exitFailed   = 2
)

const dayLayout = "2006-01-02"

var accountIDPattern = regexp.MustCompile(`^\d{12}$`)

const usageText = `Usage: ctaudit <command> [flags]

Commands:
  cloudtrail   scan CloudTrail logs for security findings and API activity
  elb          scan Elastic Load Balancing access logs (alias: alb)
  serve        run a scanner loop with /metrics for Kubernetes (serve cloudtrail|elb)

Run "ctaudit <command> -h" for the flags of a command.
`

// storeConfig is what the S3 store needs, shared by every subcommand.
type storeConfig struct {
	Bucket       string
	BucketRegion string
	Profile      string
	// Conns is the number of idle HTTP connections to keep, normally one per
	// list and fetch worker.
	Conns int
	// Log, when set, gets debug lines about the AWS config and credentials.
	Log *slog.Logger
}

// storeFactory builds the object store; tests replace it with a MemStore.
type storeFactory func(context.Context, storeConfig) (s3src.ObjectStore, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, newS3Store, time.Now()))
}

// run is main without the process globals, so tests can drive it end to end.
// The first argument selects the subcommand; there is no default.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, newStore storeFactory, now time.Time) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitFailed
	}
	switch args[0] {
	case "cloudtrail":
		return runCloudTrail(ctx, args[1:], stdout, stderr, newStore, now)
	case "elb", "alb":
		return runELB(ctx, args[1:], stdout, stderr, newStore, now)
	case "serve":
		return runServe(ctx, args[1:], stdout, stderr, newStore, time.Now)
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usageText)
		return exitOK
	}
	fmt.Fprintf(stderr, "ctaudit: unknown command %q\n\n%s", args[0], usageText)
	return exitFailed
}

// commonFlags are the flags every subcommand shares: where the logs are, which
// accounts, regions and days to scan, and how hard to scan.
type commonFlags struct {
	store                     storeConfig
	prefix                    string
	accounts, regions         string
	since, until              string
	topN                      int
	listWorkers, fetchWorkers int
	obs                       observeFlags
	log                       logFlags
}

func (c *commonFlags) register(fs *flag.FlagSet, now time.Time, bucketHelp, prefixHelp string) {
	today := now.UTC().Truncate(24 * time.Hour)
	fs.StringVar(&c.store.Bucket, "bucket", "", bucketHelp)
	fs.StringVar(&c.prefix, "prefix", "", prefixHelp)
	fs.StringVar(&c.accounts, "accounts", "", "comma-separated 12-digit account IDs (required)")
	fs.StringVar(&c.regions, "regions", "", "comma-separated regions (required)")
	fs.StringVar(&c.since, "since", today.AddDate(0, 0, -6).Format(dayLayout), "first UTC day to scan, YYYY-MM-DD")
	fs.StringVar(&c.until, "until", today.Format(dayLayout), "last UTC day to scan, YYYY-MM-DD, inclusive")
	fs.IntVar(&c.topN, "top", 10, "rows in each ranked table")
	fs.IntVar(&c.listWorkers, "list-workers", 8, "concurrent ListObjectsV2 workers")
	fs.IntVar(&c.fetchWorkers, "fetch-workers", 32, "concurrent GetObject workers")
	fs.StringVar(&c.store.Profile, "profile", "", "AWS shared config profile")
	fs.StringVar(&c.store.BucketRegion, "bucket-region", "", "region of the log bucket (defaults to the AWS config region)")
	c.obs.register(fs)
	c.log.register(fs)
}

// resolvedScope is the validated form of commonFlags.
type resolvedScope struct {
	accounts, regions []string
	// start and end are the first and last day, inclusive.
	start, end time.Time
}

func (c *commonFlags) resolve(fs *flag.FlagSet) (resolvedScope, error) {
	var r resolvedScope
	if fs.NArg() > 0 {
		return r, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if c.store.Bucket == "" {
		return r, errors.New("--bucket is required")
	}
	r.accounts = splitList(c.accounts)
	if len(r.accounts) == 0 {
		return r, errors.New("--accounts is required")
	}
	for _, a := range r.accounts {
		if !accountIDPattern.MatchString(a) {
			return r, fmt.Errorf("--accounts: %q is not a 12-digit account ID", a)
		}
	}
	r.regions = splitList(c.regions)
	if len(r.regions) == 0 {
		return r, errors.New("--regions is required")
	}

	var err error
	if r.start, err = time.Parse(dayLayout, c.since); err != nil {
		return r, fmt.Errorf("--since: want YYYY-MM-DD, got %q", c.since)
	}
	if r.end, err = time.Parse(dayLayout, c.until); err != nil {
		return r, fmt.Errorf("--until: want YYYY-MM-DD, got %q", c.until)
	}
	if r.end.Before(r.start) {
		return r, fmt.Errorf("--since %s is after --until %s", c.since, c.until)
	}
	if c.topN < 1 {
		return r, errors.New("--top must be at least 1")
	}
	if err := c.log.resolve(); err != nil {
		return r, err
	}
	c.store.Conns = c.listWorkers + c.fetchWorkers
	return r, nil
}

// checkHTMLPath rejects report paths that are clearly not meant for HTML.
func checkHTMLPath(path string) error {
	if strings.HasSuffix(strings.ToLower(path), ".txt") {
		return errors.New("--html must be an .html path, not .txt")
	}
	return nil
}

// checkPDFPath requires a .pdf suffix on a non-empty --pdf path, so a typo
// cannot overwrite some other file with PDF bytes.
func checkPDFPath(path string) error {
	if path != "" && !strings.HasSuffix(strings.ToLower(path), ".pdf") {
		return fmt.Errorf("--pdf must be a .pdf path, got %q", path)
	}
	return nil
}

// writeFile creates path and fills it with render.
func writeFile(path string, render func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	if err := render(f); err != nil {
		f.Close()
		return fmt.Errorf("write report %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close report %s: %w", path, err)
	}
	return nil
}

// warnIfEmpty tells the user when nothing was found to scan, which almost
// always means a wrong bucket, prefix, account, region, or date.
func warnIfEmpty(stderr io.Writer, objects int, scope s3src.Scope) {
	if objects > 0 {
		return
	}
	prefixes := scope.Prefixes()
	example := ""
	if len(prefixes) > 0 {
		example = fmt.Sprintf(" (e.g. s3://…/%s)", prefixes[0])
	}
	fmt.Fprintf(stderr, "ctaudit: warning: no log objects found under %d prefixes%s; check --bucket, --prefix, --accounts, --regions, and the dates\n",
		len(prefixes), example)
}

// splitList splits a comma-separated flag value, dropping blanks.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// newS3Store builds the real S3-backed store from the default AWS credential
// chain (environment, shared config, SSO, instance or pod role).
func newS3Store(ctx context.Context, cfg storeConfig) (s3src.ObjectStore, error) {
	// Keep enough idle connections for every worker; the default of a few
	// per host would force a new TLS handshake on most requests.
	conns := cfg.Conns
	httpClient := awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) {
		t.MaxIdleConns = conns
		t.MaxIdleConnsPerHost = conns
	})

	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithHTTPClient(httpClient)}
	if cfg.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Profile))
	}
	if cfg.BucketRegion != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.BucketRegion))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	if awsCfg.Region == "" {
		return nil, errors.New("no AWS region: set --bucket-region or AWS_REGION to the log bucket's region")
	}
	if cfg.Log != nil {
		// Only the provider name and expiry are logged, never the keys.
		creds, err := awsCfg.Credentials.Retrieve(ctx)
		if err != nil {
			cfg.Log.Debug("aws credentials", "region", awsCfg.Region, "profile", cfg.Profile, "err", err)
		} else {
			cfg.Log.Debug("aws credentials", "region", awsCfg.Region, "profile", cfg.Profile,
				"source", creds.Source, "expires", creds.CanExpire, "expires_at", creds.Expires)
		}
	}
	return s3src.NewS3Store(s3.NewFromConfig(awsCfg), cfg.Bucket), nil
}
