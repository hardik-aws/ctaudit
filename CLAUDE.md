# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`ctaudit` is a Go CLI that reads AWS logs straight from S3 and writes a terminal report, a single self-contained HTML report, and an optional PDF report (`--pdf`). It has two required subcommands:

- `ctaudit cloudtrail` reads gzipped CloudTrail logs. It produces security findings, forensic matches, and API volume.
- `ctaudit elb` (alias `alb`) reads Elastic Load Balancing access logs (ALB, NLB, Classic) and ALB connection logs (`conn_log_*`). It produces traffic, latency, status, client, target, and TLS statistics, plus the individual requests and connections that match the filters.

`ctaudit serve cloudtrail|elb` runs either one as a long-running scanner for Kubernetes, with Prometheus metrics on `/metrics`. Running `ctaudit` with no subcommand prints usage and exits 2. README.md documents every flag, the findings rules, and the exit codes.

## Commands

The project needs Go 1.26 or newer.

```bash
make build    # CGO_ENABLED=0, -trimpath, stripped binary at ./ctaudit
make check    # fails on unformatted files, then go vet, then go test -race
make test     # go test -race -count=1 ./...
make fmt      # gofmt -w .
make image    # docker build -t $(IMAGE):$(TAG) . (distroless, nonroot)
make helm-lint  # helm lint + rendered-kinds check on deploy/helm/ctaudit; skips without helm

# Run one test
go test -race -count=1 -run TestELBHTML ./internal/report
go test -race -count=1 -run 'TestRunELB' ./cmd/ctaudit
```

A real run needs AWS credentials from the default chain, for example `--profile gsm-shared` after `aws sso login`:

```bash
./ctaudit elb --bucket gsm-shared-services-logging-bucket --bucket-region us-east-1 \
  --accounts 702656214742 --regions us-east-1 --since 2026-09-23 --until 2026-09-23
```

## Architecture

The pipeline runs in this order: S3 scope, then the generic scan engine, then the log decoders, then per-worker aggregation, then the reports.

- **`cmd/ctaudit`**: `run()` in `main.go` is `main` without process globals. It takes a `storeFactory` and `now`, so tests drive the whole CLI end to end against `s3src.MemStore`. `commonFlags` holds the shared flags (bucket, accounts, regions, window, workers, profile). `cloudtrail.go` and `elb.go` each parse their own flags and call the matching engine function.
- **`internal/s3src`**: `ObjectStore` is the only interface for S3, with two methods, `ListPage` and `Get`. `S3Store` wraps AWS SDK v2 and `MemStore` is for tests. `Scope.Prefixes()` builds one prefix per account, region, and day: `AWSLogs/[<org-id>/]<acct>/CloudTrail/...` or `.../elasticloadbalancing/<region>/YYYY/MM/DD/`, chosen by `Scope.Service`. It never lists the bucket root, and it scans one extra day because objects are filed under their delivery day. The engine then filters records back to the exact window.
- **`internal/engine`**: `scan.go` is a generic `scan[T, S]` fan-out. List workers page through the prefixes, fetch workers gunzip and decode each object, and each fetch worker folds records into its own private shard, so the per-record path is lock-free. Per-object errors are collected and do not abort the scan. `Run` (CloudTrail) and `RunELB` each supply a `scanSpec` (key filter, decode, newShard, visit), then merge the shards. Match lists keep the earliest `--max-events` records; statistics always cover every matching record.
- **Decoders**: `internal/ctevent` handles CloudTrail records. `internal/elblog` detects the log format from the object key (`app.` means ALB, `net.` means NLB, anything else is Classic, `conn_log` means a connection log). It produces `elblog.Entry`, where `Conn` marks connection-log rows. An unknown latency is stored as `-1`, not `0`. `elblog.Filter` has `Match` for requests and `MatchConn` for connections. Only the client IP and the time window apply to connections.
- **Aggregation**: `internal/stats` provides `Counter` (`map[string]int`), `ELBSummary` (requests), and `ConnSummary` (TLS connections). Connection records never change request totals. CloudTrail filtering is in `internal/query` and the security rules are in `internal/findings`. CRITICAL findings stay visible even past the findings cap.
- **Observability**: `internal/sink` has no dependency outside the stdlib. `Loki`, `JSONL`, and `Multi` implement `Sink`, whose per-worker `Writer` gets each line; `Pushgateway` posts a `Metrics` text body. `cmd/ctaudit/observe.go` builds them from `--loki`, `--jsonl`, and `--pushgateway` before any S3 call and hands the engine an `Emit` hook, which receives every match uncapped. Credentials come only from `CTAUDIT_LOKI_*` and `CTAUDIT_PUSHGATEWAY_*` env vars. A failed push exits 2.
- **Debug logging**: `--debug` or `CTAUDIT_DEBUG=1` builds a `log/slog` logger (`cmd/ctaudit/debug.go`, `--log-format text|json`) on stderr and threads it through `Options.Debug`/`ELBOptions.Debug`, `storeConfig.Log`, the sinks' `Log` fields, and the serve `server`. A nil logger means debug is off and costs nothing, so every call site must stay nil-safe (`debugLog`). Never log credentials, headers, or record contents; sink URLs go through `redactURL`. Tests in the `debug_test.go` files assert this.
- **Serve mode**: `cmd/ctaudit/serve.go` parses `serve <sub>` through the subcommand parser's `extra` hook and the `set` map of explicit flags (it rejects `--since`, `--until`, `--html`, `--pdf`, `--pushgateway`, `--jsonl`, `--fail-on`). `server.loop` runs one tick at start and one per trigger, never overlapping. Each tick scans `[now-lookback, now]` with `Skip = state.isSeen`, and commits (`serveState.commit`: keys seen, counters added, result stored for `/report`) only when the tick's Loki sink closes cleanly; otherwise `fail` records nothing, so the tick is retried. `cmd/ctaudit/serve_state.go` holds the seen set, counters, and `/metrics` rendering and has no HTTP or S3 code. State is in memory only. Tests drive `tick` with a fake clock and `handler()` with httptest.
- **Deployment**: `Dockerfile` builds into `distroless/static-debian12:nonroot`. `deploy/helm/ctaudit` renders one single-replica `Recreate` Deployment and ClusterIP Service per `scanners[]` entry, an IRSA ServiceAccount, an optional Loki Secret (loaded with `envFrom`), and optional ServiceMonitor and PrometheusRule. `docs/grafana/ctaudit-serve-alerts.yaml` must stay in step with `templates/prometheusrule.yaml`.
- **`internal/report`**: `terminal.go`/`html.go` render CloudTrail and `elb.go` renders ELB. The HTML uses `html/template` with `go:embed` files from `templates/`: `report.html.tmpl` and `style.css` for CloudTrail, and `elb.html.tmpl`, `elb.css`, and `elb.js` for ELB. The CSS and JS are inlined into the page. `baseFuncs()` holds the shared template functions and the ELB report adds its own (`bytes`, `latency`, `tone`, and others). `tone()` maps status codes, TLS versions, and verify statuses to the pill classes `ok`, `info`, `warn`, and `crit`. The PDF is built with gopdf: `pdf.go` holds the `pdfDoc` layout helper (the only file that imports gopdf) and embeds the Go fonts from `fonts/`, and `elb_pdf.go` and `ct_pdf.go` fill it from the same ranked tables and hourly bars. gopdf stores text as glyph IDs, so PDF tests assert on `pdfDoc.drawn`, not on the bytes.

## Constraints

- AWS access is read-only: only `s3:ListBucket`, `s3:GetObject`, and `kms:Decrypt` for SSE-KMS CloudTrail. No Glue, no Athena, no other query service. Everything runs in-process.
- The only third-party dependencies are AWS SDK v2 and `github.com/signintech/gopdf` (which brings `gofpdi` and `pkg/errors`). Do not add others.
- The HTML report must stay self-contained, with no `<link` and no external `src="http`. Log-derived text such as user agents must be HTML-escaped. `TestELBHTML` asserts both.
- Exit codes: 0 means OK. 1 means a CloudTrail finding is at or above `--fail-on`. 2 means a failure, including any unreadable object, because a partial scan must never pass a CI gate.
- `iam/cloudtrail-audit-reader` is a Terraform module for the least-privilege reader policy. Do not run `terraform plan` or `terraform apply` from here.
- Each serve scanner must stay at exactly one replica: two pods would send every Loki line twice. Never apply the chart or anything else to a cluster from here.
- Plans for past features are in `docs/superpowers/plans/`.
- Do not commit the `./ctaudit` binary or generated reports (`ctaudit-report.html`, `elb-report.html`, `*.pdf`).
