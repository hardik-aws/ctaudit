# ctaudit

`ctaudit` reads AWS logs straight from S3 and prints a report, then writes the same report to a single self-contained HTML file. It has two commands:

- `ctaudit cloudtrail` reads gzipped CloudTrail logs and reports security findings, forensic matches, and API volume.
- `ctaudit elb` (alias `ctaudit alb`) reads Elastic Load Balancing access logs from Application, Network, and Classic Load Balancers. It reports traffic, latency, status codes, clients, targets, and TLS usage, and lists the individual requests that match forensic filters.
- `ctaudit serve cloudtrail|elb` runs either one as a long-running scanner with Prometheus metrics, for Kubernetes. See [Running on Kubernetes](#running-on-kubernetes).

The command is required. Running `ctaudit` alone prints usage and exits 2. It uses no AWS Glue, no Athena, and no other query service. Everything runs in-process against objects read from the log bucket.

## Build

Requires Go 1.26 or newer.

```bash
make build        # produces ./ctaudit
make check        # gofmt check, go vet, go test -race
```

## CloudTrail

```bash
ctaudit cloudtrail --bucket org-cloudtrail-logs --org-id o-abc123 \
        --accounts 111122223333,444455556666 \
        --regions us-east-1,eu-central-1 \
        --since 2026-09-14 --until 2026-09-20
```

This prints the terminal summary and writes `ctaudit-report.html`.

### Who deleted or changed something?

```bash
# Every mutating call that touched a resource whose ARN or request parameters contain "my-bucket"
ctaudit cloudtrail --bucket org-cloudtrail-logs --org-id o-abc123 \
        --accounts 111122223333 --regions us-east-1 \
        --resource my-bucket --writes-only

# Everything one principal did from one address
ctaudit cloudtrail ... --principal alice --source-ip 203.0.113.44

# Specific API calls
ctaudit cloudtrail ... --event DeleteBucket,PutBucketPolicy
```

A narrowing filter (`--principal`, `--resource`, `--source-ip`, `--event`, or `--errors-only`) adds a matching events table to both reports. The table is capped at `--max-events`.

### CI gating

```bash
ctaudit cloudtrail ... --html "" --fail-on high
```

This exits 1 if any finding is HIGH or CRITICAL.

### CloudTrail flags

| Flag | Default | Meaning |
|---|---|---|
| `--bucket` | required | CloudTrail log bucket |
| `--accounts` | required | Comma-separated 12-digit account IDs |
| `--regions` | required | Comma-separated regions |
| `--org-id` | | Organization ID for an organization trail, e.g. `o-abc123` |
| `--prefix` | | Key prefix configured on the trail, before `AWSLogs/` |
| `--since` | today minus 6 days | First UTC day, `YYYY-MM-DD` |
| `--until` | today | Last UTC day, `YYYY-MM-DD`, inclusive |
| `--principal` | | Actor contains this text (case-insensitive) |
| `--resource` | | Resource ARN or request parameters contain this text |
| `--source-ip` | | Source IP contains this text |
| `--event` | | Comma-separated event names (exact, case-insensitive) |
| `--source` | | Comma-separated event sources, e.g. `s3.amazonaws.com` or `s3` |
| `--errors-only` | false | Only events that returned an error code |
| `--writes-only` | false | Only mutating events |
| `--html` | `ctaudit-report.html` | HTML report path. `""` skips it. Must not end in `.txt` |
| `--pdf` | | Also write a printable PDF report to this path. Must end in `.pdf` |
| `--top` | 10 | Rows per ranked table |
| `--max-events` | 200 | Matching events kept for the events table |
| `--fail-on` | `none` | Exit 1 when a finding is at or above `low`, `medium`, `high`, or `critical` |
| `--list-workers` | 8 | Concurrent `ListObjectsV2` workers |
| `--fetch-workers` | 32 | Concurrent `GetObject` workers |
| `--profile` | | AWS shared config profile |
| `--bucket-region` | AWS config region | Region of the log bucket |
| `--debug` | off | Log each step of the scan to stderr; see [Debug logging](#debug-logging) |
| `--log-format` | `text` | Debug log format: `text` or `json` |

CloudTrail files each object under the day it was delivered, not the day of the events inside it. Events from late on `--until` can therefore land in the next day's prefix. `ctaudit` scans one extra day of prefixes and filters back to the exact window.

### Findings

| Rule | Severity | Fires on |
|---|---|---|
| `root-usage` | CRITICAL | Root account API call not made by an AWS service |
| `cloudtrail-tamper` | CRITICAL | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `DeleteEventDataStore` |
| `console-no-mfa` | HIGH | Successful console login without MFA |
| `access-key-created` | HIGH | `iam:CreateAccessKey` |
| `s3-exposure` | HIGH | Bucket policy, ACL, or public access block changes |
| `sg-open-ingress` | HIGH | Security group ingress opened to `0.0.0.0/0` or `::/0` |
| `kms-destruction` | HIGH | KMS key disabled, scheduled for deletion, alias deleted, or rotation disabled |
| `console-login-failed` | MEDIUM | Failed console login |
| `iam-mutation` | MEDIUM | Any mutating IAM call |
| `access-denied` | LOW | `AccessDenied` and `UnauthorizedOperation` errors |

## Elastic Load Balancing

```bash
ctaudit elb --bucket example-alb-logs --bucket-region us-east-1 \
            --accounts 111122223333 --regions us-east-1 \
            --since 2026-09-23 --until 2026-09-23
```

This reads every access log object under `AWSLogs/<account>/elasticloadbalancing/<region>/YYYY/MM/DD/`, prints the terminal summary, and writes `elb-report.html`. The log format is detected per object from its key: `app.` objects are ALB logs, `net.` objects are NLB logs, and the rest are Classic Load Balancer logs.

The report contains:

- Traffic totals: requests, bytes received and sent, and latency percentiles
- Ranked tables: load balancers, ELB and target status codes, client IPs, hosts, normalized paths, user agents, targets, methods, request types, actions, TLS protocols and ciphers, and error reasons
- Health: average target response time (warn 500 ms, crit 1 s), 5xx rate (warn 1%, crit 5%), target connection errors (a `TargetConnection*` error reason, or a 502 with a target and no target status), and how many of the targets seen returned a 5xx. Access logs carry no health-check results, so this is not the healthy host count CloudWatch shows
- Timeline charts over the scanned window, in 1 minute to 1 day buckets (at most 288): requests with the average target response time, responses by ELB status class, target responses with connection errors, and average and maximum latency against the 500 ms and 1 s guides. Each chart has a min, max, average, and last value legend
- Target groups: requests, target 2xx, 4xx, and 5xx, ELB 5xx, connection errors, distinct targets, and average and maximum target response time
- Slowest paths: normalized paths ordered by average latency, with minimum and maximum
- Requests by hour (UTC)
- TLS connections, from ALB connection logs (`conn_log_*` objects): total and TLS connections, failed TLS handshakes on port 443, handshake time, and ranked tables by load balancer, listener and TLS protocol, protocol, cipher, key exchange, client certificate verify status, client IP, and failed-handshake client IP
- In the HTML report, a requests table with every log field and a connections table with every connection log field, each capped at `--max-events`
- In the HTML report, share rings for ELB status class, load balancer, method, and listener type, and the error (5xx) and warning (4xx) requests from the kept matches, up to 200 each

Connection records are counted separately from requests, so they never change request totals. Only `--client-ip` and the time window apply to them; any other request filter excludes every connection.

### Forensics

```bash
# Every 5xx from one load balancer
ctaudit elb ... --lb web --status 5xx

# What one client did
ctaudit elb ... --client-ip 203.0.113.224

# Slow requests to one host
ctaudit elb ... --host tile-staging.terrastride.com --slower-than 1s

# Scanners probing for WordPress
ctaudit elb ... --path wp-login --method GET,POST
```

Any filter, including `--lb` and `--type`, adds matching requests and connections tables to the terminal report. The HTML report always lists them. The table keeps the earliest `--max-events` requests. The statistics always cover every matching request.

### ELB flags

`--bucket`, `--accounts`, `--regions`, `--prefix`, `--since`, `--until`, `--top`, `--list-workers`, `--fetch-workers`, `--profile`, `--bucket-region`, `--debug`, and `--log-format` work as they do for CloudTrail. `--prefix` is the prefix configured in the load balancer's access log settings.

| Flag | Default | Meaning |
|---|---|---|
| `--lb` | | Comma-separated load balancer names. An object is read when its name contains any of them (case-insensitive) |
| `--type` | all | Comma-separated load balancer types: `alb`, `nlb`, `classic` |
| `--client-ip` | | Client IP contains this text |
| `--host` | | Host header or TLS SNI domain contains this text (case-insensitive) |
| `--path` | | URL path contains this text (case-insensitive) |
| `--method` | | Comma-separated HTTP methods, e.g. `GET,POST` |
| `--status` | | Comma-separated ELB status codes or classes, e.g. `502,4xx` |
| `--target` | | Target `ip:port` contains this text |
| `--user-agent` | | User agent contains this text (case-insensitive) |
| `--slower-than` | | Total latency at least this long, e.g. `500ms` or `2s`. Requests with unknown latency never match |
| `--html` | `elb-report.html` | HTML report path. `""` skips it. Must not end in `.txt` |
| `--pdf` | | Also write a printable PDF report to this path. Must end in `.pdf` |
| `--max-events` | 200 | Matching requests, and separately matching connections, kept for their tables |

Load balancers write one object per five-minute interval and file it under the day that interval ended. Like the CloudTrail command, `ctaudit elb` scans one extra day of prefixes and filters back to the exact window.

`ctaudit elb` has no security findings and no `--fail-on`. It exits 0 on a complete scan and 2 on failure.

## PDF report

Both subcommands take `--pdf <path>` to write a printable A4 report next to the HTML one. It holds the summary, the ELB health values, timeline charts, target group and slowest path tables, the hourly chart, the ranked tables, and, for CloudTrail, every finding the report kept. It leaves out the matching requests, connections, and events tables; use the HTML report for those. A PDF write failure exits 2.

## Prometheus and Loki

Both subcommands can push their results into an existing Prometheus and Grafana stack. The one-shot commands listen on no port: ctaudit pushes run metrics to a Prometheus Pushgateway and streams every matching record to the Loki push API, then exits. Both outputs are off unless you set their flags.

| Flag | Meaning |
|---|---|
| `--pushgateway URL` | Pushgateway base URL, e.g. `http://pushgateway.monitoring:9091` |
| `--push-job NAME` | Pushgateway job name and Loki `job` label (default `ctaudit`) |
| `--loki URL` | Loki base URL, e.g. `http://loki-gateway.monitoring`; lines go to `<URL>/loki/api/v1/push` |
| `--loki-tenant ID` | Sends the `X-Scope-OrgID` header for multi-tenant Loki |
| `--loki-time scan\|event` | Timestamp of each Loki line: `scan`, the time ctaudit shipped it (default for one-shot runs), or `event`, the request or event time (default under `serve`) |
| `--jsonl PATH` | Also writes every Loki line to a local JSON Lines file |

Credentials come only from the environment, never from flags, so they stay out of shell history and process listings. Set a user and password for basic auth, or a token for bearer auth. Setting both for the same target is an error.

| Variable | Meaning |
|---|---|
| `CTAUDIT_LOKI_USER`, `CTAUDIT_LOKI_PASSWORD` | Basic auth for Loki |
| `CTAUDIT_LOKI_TOKEN` | Bearer token for Loki |
| `CTAUDIT_PUSHGATEWAY_USER`, `CTAUDIT_PUSHGATEWAY_PASSWORD` | Basic auth for the Pushgateway |
| `CTAUDIT_PUSHGATEWAY_TOKEN` | Bearer token for the Pushgateway |

```bash
CTAUDIT_LOKI_TOKEN=... ./ctaudit cloudtrail --bucket org-trail --accounts 111122223333 \
  --regions us-east-1 --since 24h \
  --pushgateway http://pushgateway.monitoring:9091 \
  --loki http://loki-gateway.monitoring --loki-tenant security
```

**Loki.** Every record that passes the filters is sent, uncapped by `--max-events`, and for `cloudtrail` every finding follows at the end. Labels stay low-cardinality: `job`, `subcommand`, `kind` (`event`, `finding`, `request`, or `conn`), plus `account` and `region` on CloudTrail events, `severity` and `account` on findings, and `lb` on ELB lines. Each line is a JSON object with `kind`, `run_id`, and the record's fields. CloudTrail events keep CloudTrail's field names; findings and ELB lines use snake_case. The line always carries the record time (`event_time` or CloudTrail's `eventTime`). With `--loki-time scan` each entry is stamped with the scan time, so Loki accepts any window. With `--loki-time event` each entry is stamped with its record time, so Grafana's time picker and over-time charts follow request and event times. Loki accepts a stream's entries only in order, within an out-of-order window of half `max_chunk_age` (1 hour by default), and refuses entries older than `reject_old_samples_max_age` (7 days by default). So in event mode ctaudit holds every line until the scan ends (at most 2,000,000; past that the run fails and asks for `--loki-time scan` or a shorter window), sorts each stream oldest first, and pushes one batch at a time. When Loki still refuses entries for their age, it keeps the rest of the push; ctaudit prints a warning with the count instead of failing, because a retry cannot make an entry younger. Keep event-mode windows inside the 7-day limit, or raise it in Loki. CloudTrail lines over 128 KiB drop `requestParameters`, `responseElements`, and `additionalEventData` and carry `"truncated": true`.

```logql
{job="ctaudit", kind="finding", severity="critical"} | json | line_format "{{.rule}} {{.actor}} {{.title}}"
{job="ctaudit", subcommand="elb", kind="request"} | json | elb_status =~ "5.." | line_format "{{.client_ip}} {{.method}} {{.url}}"
{job="ctaudit", kind="event"} | json | userIdentity_type = "Root"
```

**Pushgateway.** Metrics are pushed once per run to `/metrics/job/<job>/subcommand/<cloudtrail|elb>`, so the two subcommands never overwrite each other. Every run sends `ctaudit_objects_scanned`, `ctaudit_records_read`, `ctaudit_records_matched`, `ctaudit_scan_errors`, `ctaudit_scan_duration_seconds`, and `ctaudit_last_run_timestamp_seconds`. `ctaudit_last_success_timestamp_seconds` is sent only when the scan had no errors and the Loki and JSONL output worked, so an earlier success stays in place after a failed run. `cloudtrail` adds `ctaudit_findings{severity}`, `ctaudit_findings_dropped`, `ctaudit_cloudtrail_write_events`, and `ctaudit_cloudtrail_error_events`. `elb` adds `ctaudit_elb_requests{status_class}`, byte and latency gauges, and TLS connection gauges. Labeled families always carry every label value, with zeros, so no stale series survive.

A bad URL, job name, or credential variable exits 2 before any S3 call. A failed Loki or Pushgateway push also exits 2, after the reports are written. `docs/grafana/` holds an example dashboard and Prometheus alert rules.

**Report dashboards.** [`deploy/helm/ctaudit/dashboards/`](deploy/helm/ctaudit/dashboards) holds two Grafana dashboards that rebuild the HTML reports from the Loki lines alone, with no Prometheus needed:

- `ctaudit-elb-report.json` (uid `ctaudit-elb-report`) shows the traffic totals, 4xx and 5xx counts, and average and maximum latency. It has every request table from the HTML report (load balancer, ELB and target status, client IPs, hosts, normalized paths, user agents, targets, method, listener type, action, TLS protocol and cipher, error reasons) and the TLS connection tables, including failed 443 handshakes by client IP. A Failing requests section, driven by the `Failing status` variable (4xx and 5xx, 5xx only, or 4xx only), shows the failing count and share, failing requests by status, path, client IP, target, error reason, and load balancer, and the failing request lines with their error reason and trace ID. It ends with the matching requests and connections as rows.
- `ctaudit-cloudtrail-report.json` (uid `ctaudit-cloudtrail-report`) shows the event, write, and error totals and the findings by severity, rule, actor, and account. It has the principal, event name, service, error code, source IP, account, and region tables, and the matching findings and events as rows.

Both take a `loki` data source variable and filter on job, load balancer or account and region, and regular expressions for client IP and ELB status, or principal and event name. `Top N` sets the table length. The counts use the same rules as the HTML report: the principal is the ARN, else `invokedBy`, else `userName`, else `principalId`; numeric path segments become `{n}`; a write event is `readOnly=false`, or a missing `readOnly` and an event name that is not a read verb. Two limits apply. The time picker selects Loki timestamps: request and event times for lines shipped with `--loki-time event` (the `serve` default), but scan runs for lines shipped with the one-shot default `--loki-time scan`, whose over-time charts show when lines were shipped. Tables that group by a high-cardinality field, such as client IP on a busy load balancer, can reach Loki's `max_query_series` limit (500 by default); lower `Top N` does not help there, so narrow the filters or the time range. Import the files in Grafana, or set `grafanaDashboards.enabled: true` in the chart to ship them as a ConfigMap for the Grafana dashboard sidecar.

## Debug logging

`--debug`, or `CTAUDIT_DEBUG=1` in the environment, makes `cloudtrail`, `elb`, and `serve` log what they do to stderr. The reports on stdout and in files are unchanged. `--log-format json` writes one JSON object per line for log collectors; the default is `text` (`key=value`).

The log shows:

- the scan scope, window, prefix count, and worker counts, and where the AWS credentials came from and when they expire
- one line per listed prefix, with the keys listed, kept for fetching, filtered out by key, and skipped as already seen by `serve`
- one line per object, with its key, compressed bytes, records read, records matched, and duration, or the S3 error
- one line per Loki or Pushgateway push attempt, with the line count, bytes, HTTP result, duration, and whether it retries
- for `serve`, the start and end of each tick with its window, whether it committed and why, pruned state, and every HTTP request

It never logs credentials, request headers, or record contents, and URLs have any user info redacted. AWS SDK request logging stays off because it would print signed headers. Debug output is verbose: expect one line per object, so a first `serve` tick over a long lookback can log thousands of lines.

```bash
./ctaudit elb --bucket alb-access-logs --accounts 111122223333 --regions us-east-1 --since 2026-09-23 --until 2026-09-23 --debug 2>debug.log
```

## Running on Kubernetes

`ctaudit serve` turns either subcommand into a long-running scanner for Kubernetes. It rescans a rolling window on a fixed interval, keeps running totals as Prometheus counters on `/metrics`, and streams new matches to Loki. The Helm chart in [`deploy/helm/ctaudit`](deploy/helm/ctaudit) runs one pod per scanner.

```bash
./ctaudit serve cloudtrail --bucket org-trail --accounts 111122223333 --regions us-east-1 \
  --interval 15m --lookback 24h --loki http://loki-gateway.monitoring
./ctaudit serve elb --bucket alb-logs --accounts 111122223333 --regions us-east-1 --lb tiles
```

`serve` takes every flag of the named subcommand plus three of its own:

| Flag | Default | Meaning |
|---|---|---|
| `--interval` | `15m` | Time between the start of one scan and the next. Minimum `1m`. |
| `--lookback` | `24h` | Size of the rolling window. At least `--interval`, at most `720h`. |
| `--listen` | `:8080` | HTTP listen address |

`--since`, `--until`, `--html`, `--pdf`, `--pushgateway`, `--jsonl`, and `--fail-on` make no sense for a server and exit 2 if set. `--loki`, `--loki-tenant`, and `--push-job` work as in the one-shot commands; `--loki-time` defaults to `event` here.

**Incremental scans.** The first scan starts at once. Each scan covers `[now - lookback, now]`, lists the same day prefixes a one-shot run would, and skips every object key an earlier scan already read, so a steady-state scan fetches only newly delivered objects. S3 log objects are immutable, and late deliveries arrive as new keys. A scan commits only after its Loki push succeeds: if Loki fails, no key is marked as read and the next scan retries the whole batch, so lines may be duplicated but are never lost. Objects that fail to read are retried on every scan. Scans never overlap.

**Restarts.** State lives in memory only. After a restart the first scan reads the whole lookback window again, Loki receives those lines a second time, and the counters start from zero, which `rate()` and `increase()` handle.

**Endpoints.** There is no authentication, so keep the Service ClusterIP.

| Path | Response |
|---|---|
| `/metrics` | Prometheus text: `ctaudit_scans_total{result}` (`ok`, `partial`, `failed`), object, record, and error counters, `ctaudit_findings_total{severity}`, `ctaudit_elb_requests_total{status_class}`, latency and TLS counters, `ctaudit_last_success_timestamp_seconds`, and `ctaudit_seen_keys`. Every family has a `subcommand` label. |
| `/report` | The usual self-contained HTML report for the whole window, merged from every scan in it. 503 until the first scan commits. |
| `/healthz` | `ok` while the process runs. It is not tied to scan success: a failing scan raises an alert, not a restart. |

SIGTERM stops the running scan, flushes Loki, and exits 0 after at most 10 seconds.

### Image

`make image` builds a static binary into `gcr.io/distroless/static-debian12:nonroot`, which runs as UID 65532. Set `IMAGE` and `TAG` to your registry, then push it yourself:

```bash
make image IMAGE=111122223333.dkr.ecr.us-east-1.amazonaws.com/ctaudit TAG=0.1.1
docker push 111122223333.dkr.ecr.us-east-1.amazonaws.com/ctaudit:0.1.1
```

### IAM role for service accounts

The pods get AWS credentials through IRSA. Create a role whose trust policy lets the chart's ServiceAccount (`<release>-ctaudit` by default, or just the release name when it already contains `ctaudit`) assume it through the cluster's OIDC provider, and attach the [`iam/cloudtrail-audit-reader`](iam/cloudtrail-audit-reader) policy:

```hcl
data "aws_iam_policy_document" "ctaudit_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider}:sub"
      values   = ["system:serviceaccount:security:ctaudit"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ctaudit" {
  name               = "ctaudit-reader"
  assume_role_policy = data.aws_iam_policy_document.ctaudit_trust.json
}

resource "aws_iam_role_policy_attachment" "ctaudit" {
  role       = aws_iam_role.ctaudit.name
  policy_arn = module.ctaudit_reader.policy_arn
}
```

### Helm chart

Each entry in `scanners` becomes one Deployment and one ClusterIP Service. Each Deployment runs exactly one replica with the `Recreate` strategy, because two pods would send every line to Loki twice. The chart also renders the IRSA ServiceAccount, a Secret for Loki credentials when `loki.auth` is set, and, when enabled, a Prometheus Operator ServiceMonitor and a PrometheusRule with the serve alerts. `deploy/helm/ctaudit/values.yaml` documents every value.

```yaml
# values-prod.yaml
image:
  repository: 111122223333.dkr.ecr.us-east-1.amazonaws.com/ctaudit
  tag: "0.1.1"
serviceAccount:
  roleArn: arn:aws:iam::111122223333:role/ctaudit-reader
aws:
  bucket: org-cloudtrail-logs
  bucketRegion: us-east-1
  accounts: ["111122223333", "444455556666"]   # quote account IDs
  regions: ["us-east-1", "eu-west-1"]
loki:
  url: http://loki-gateway.monitoring
  tenant: security
  existingSecret: ctaudit-loki                  # holds CTAUDIT_LOKI_TOKEN
scanners:
  - name: cloudtrail
    subcommand: cloudtrail
    args: ["--org-id", "o-abc123"]
  - name: alb
    subcommand: elb
    bucket: alb-access-logs
    interval: 5m
    lookback: 6h
    args: ["--lb", "tiles"]
serviceMonitor:
  enabled: true
  labels:
    release: kube-prometheus-stack
prometheusRule:
  enabled: true
  labels:
    release: kube-prometheus-stack
```

```bash
helm upgrade --install ctaudit deploy/helm/ctaudit -n security --create-namespace -f values-prod.yaml
kubectl -n security port-forward svc/ctaudit-cloudtrail 8080:8080   # then open localhost:8080/report
```

Set `debug: true` to pass `--debug` to every scanner, and `logFormat: json` to pass `--log-format json`; a scanner entry can override either. The debug lines go to the pod log.

[`deploy/terraform/example`](deploy/terraform/example) is an example Terraform root module that creates the IRSA role and reader policies and installs the chart with the role ARN passed in.

The pods run as non-root with a read-only root filesystem, drop every capability, and do not mount a Kubernetes API token. `make helm-lint` lints the chart and checks what it renders. `grafanaDashboards.enabled: true` adds a ConfigMap labeled `grafana_dashboard: "1"` that carries the two report dashboards; set `grafanaDashboards.namespace` when the Grafana sidecar watches a different namespace, and `grafanaDashboards.annotations` for a folder, for example `grafana_folder: Security`. `docs/grafana/ctaudit-serve-dashboard.json` and `docs/grafana/ctaudit-serve-alerts.yaml` are the serve-mode dashboard and alert rules; the alert rules are the same ones the chart's PrometheusRule carries.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed; for `cloudtrail`, no findings at or above `--fail-on` |
| 1 | `cloudtrail` only: scan completed; findings at or above `--fail-on` exist |
| 2 | Scan failed: missing command, bad flags, AWS error, unreadable objects, or a failed Loki or Pushgateway push |

Unreadable objects return 2 even when findings exist, because the report may be incomplete. A CI gate must not pass on a partial scan.

## IAM

`ctaudit` is read-only. It needs `s3:ListBucket` on the log bucket (restricted to the `AWSLogs/` prefix) and `s3:GetObject` on the log objects. It also needs `kms:Decrypt` when the trail uses SSE-KMS. The `elb` command needs the same two S3 permissions on the access log bucket. ELB access logs support only SSE-S3 encryption, so it never needs KMS. It never writes to the bucket or changes any AWS resource.

The Terraform module in [`iam/cloudtrail-audit-reader`](iam/cloudtrail-audit-reader) creates that policy. Point `log_bucket_name` at the access log bucket to use it for `ctaudit elb`:

```hcl
module "ctaudit_reader" {
  source          = "./iam/cloudtrail-audit-reader"
  log_bucket_name = "org-cloudtrail-logs"
  kms_key_arn     = "arn:aws:kms:us-east-1:111122223333:key/..." # omit for SSE-S3
  policy_name     = "ctaudit-reader-cloudtrail"                  # unique per account
  tags = {
    Owner       = "platform-team"
    Department  = "engineering"
    Project     = "example-project"
    Application = "ctaudit"
    ManagedBy   = "terraform"
  }
}
```

Credentials come from the default AWS chain: environment variables, shared config and SSO, or an instance or pod role.

## Cost

The only AWS charges are S3 `LIST` and `GET` requests. `ctaudit` never lists the bucket root. It lists one prefix per account, region, and day, so a narrow scan touches only the objects it needs. At us-east-1 pricing, `GET` costs about $0.0004 per 1,000 requests, so a full scan of ~500,000 objects costs about $0.20. Data transfer is free when `ctaudit` runs in the bucket's region.
