# Grafana, Loki, and the Pushgateway

All five subcommands can push their results into an existing Prometheus, Loki, and Grafana stack. This page covers how to send the data, what the Loki lines look like, and the Grafana dashboards that read them. The metric names are in [Prometheus metrics](prometheus-metrics.md); running ctaudit as a scanner is in [Kubernetes](kubernetes.md).

## Sending data

The one-shot commands listen on no port: ctaudit pushes run metrics to a Prometheus Pushgateway and streams every matching record to the Loki push API, then exits. Under `ctaudit serve`, Prometheus scrapes `/metrics` instead, and Loki works the same way. Both outputs are off unless you set their flags.

| Flag | Meaning |
|---|---|
| `--pushgateway URL` | Pushgateway base URL, e.g. `http://pushgateway.monitoring:9091`. Not allowed under `serve` |
| `--push-job NAME` | Pushgateway job name and Loki `job` label (default `ctaudit`) |
| `--loki URL` | Loki base URL, e.g. `http://loki-gateway.monitoring`; lines go to `<URL>/loki/api/v1/push` |
| `--loki-tenant ID` | Sends the `X-Scope-OrgID` header for multi-tenant Loki |
| `--loki-time scan\|event` | Timestamp of each Loki line: `scan`, the time ctaudit shipped it (default for one-shot runs), or `event`, the request or event time (default under `serve`) |
| `--jsonl PATH` | Also writes every Loki line to a local JSON Lines file. Not allowed under `serve` |
| `--emit-flows reject\|all\|none` | `vpc` only: which matching flows are sent to Loki and JSONL (default `reject`) |

Credentials come only from the environment, never from flags, so they stay out of shell history and process listings. Set a user and password for basic auth, or a token for bearer auth. Setting both for the same target is an error.

| Variable | Meaning |
|---|---|
| `CTAUDIT_LOKI_USER`, `CTAUDIT_LOKI_PASSWORD` | Basic auth for Loki |
| `CTAUDIT_LOKI_TOKEN` | Bearer token for Loki |
| `CTAUDIT_PUSHGATEWAY_USER`, `CTAUDIT_PUSHGATEWAY_PASSWORD` | Basic auth for the Pushgateway |
| `CTAUDIT_PUSHGATEWAY_TOKEN` | Bearer token for the Pushgateway |

```bash
CTAUDIT_LOKI_TOKEN=... ./ctaudit cloudtrail --bucket org-trail --accounts 111122223333 \
  --regions us-east-1 --since 2026-09-27 --until 2026-09-28 \
  --pushgateway http://pushgateway.monitoring:9091 \
  --loki http://loki-gateway.monitoring --loki-tenant security
```

A bad URL, job name, or credential variable exits 2 before any S3 call. A failed Loki or Pushgateway push also exits 2, after the reports are written.

## Loki lines

Every record that passes the filters is sent, uncapped by `--max-events`, and for `cloudtrail`, `waf`, `s3`, and `vpc` every finding follows at the end.

**Labels** stay low-cardinality. Every stream has `job`, `subcommand`, and `kind`. The rest depend on the kind:

| `kind` | Subcommand | Extra labels |
|---|---|---|
| `event` | `cloudtrail` | `account`, `region` |
| `finding` | `cloudtrail`, `waf`, `s3`, `vpc` | `severity`, `account` |
| `request` | `elb` | `lb` |
| `conn` | `elb` (ALB connection logs) | `lb` |
| `request` | `waf` | `acl`, `action` |
| `request` | `s3` | `bucket`, `status_class` |
| `flow` | `vpc` | `action`, `vpc` |

**Lines.** Each line is a JSON object with `kind`, `run_id`, and the record's fields. CloudTrail events keep CloudTrail's field names; findings, ELB lines, WAF lines, S3 lines, and VPC flow lines use snake_case. The line always carries the record time (`event_time`, or CloudTrail's `eventTime`). CloudTrail lines over 128 KiB drop `requestParameters`, `responseElements`, and `additionalEventData` and carry `"truncated": true`. WAF lines keep only the `Host` and `User-Agent` headers, and S3 lines have query strings removed, because those fields are dropped at decode time.

**VPC flows.** `--emit-flows` controls which matching flows are sent: `reject` (the default) sends only REJECT flows; `all` sends every matching flow, which can produce millions of lines per hour on a busy VPC; `none` sends no flows. Findings are always sent.

### `--loki-time`

With `--loki-time scan` each entry is stamped with the time it was shipped, so Loki accepts any window, but over-time charts show when lines were shipped rather than when requests happened. With `--loki-time event` each entry is stamped with its record time, so Grafana's time picker and over-time charts follow request, event, and flow times. Use `event` when you want the dashboards below to line up with real traffic; it is the default under `serve`.

Loki accepts a stream's entries only in order, within an out-of-order window of half `max_chunk_age` (1 hour by default), and refuses entries older than `reject_old_samples_max_age` (7 days by default). So in event mode ctaudit holds every line until the scan ends (at most 2,000,000; past that the run fails and asks for `--loki-time scan` or a shorter window), sorts each stream oldest first, and pushes one batch at a time. When Loki still refuses entries for their age, it keeps the rest of the push; ctaudit prints a warning with the count instead of failing, because a retry cannot make an entry younger. Keep event-mode windows inside the 7-day limit, or raise it in Loki.

Event-time lines carry no scan time, so shipping the same window twice in event mode doubles every count; give a re-run its own `--push-job`.

### Example LogQL

```logql
{job="ctaudit", kind="finding", severity="critical"} | json | line_format "{{.rule}} {{.actor}} {{.title}}"
{job="ctaudit", subcommand="elb", kind="request"} | json | elb_status =~ "5.." | line_format "{{.client_ip}} {{.method}} {{.url}}"
{job="ctaudit", subcommand="waf", kind="request"} | json | action = "BLOCK" | line_format "{{.client_ip}} {{.rule}} {{.uri}}"
{job="ctaudit", subcommand="s3", kind="request", status_class="4xx"} | json | status = "403" | line_format "{{.remote_ip}} {{.requester}} {{.key}}"
{job="ctaudit", subcommand="vpc", kind="flow", action="REJECT"} | json | line_format "{{.source}} -> {{.destination}}:{{.dst_port}}"
{job="ctaudit", kind="event"} | json | userIdentity_type = "Root"
```

## Dashboards

| File | Data sources | For |
|---|---|---|
| [`deploy/helm/ctaudit/dashboards/ctaudit-cloudtrail-report.json`](../deploy/helm/ctaudit/dashboards/ctaudit-cloudtrail-report.json) | Loki | CloudTrail report rebuilt from Loki lines |
| [`deploy/helm/ctaudit/dashboards/ctaudit-elb-report.json`](../deploy/helm/ctaudit/dashboards/ctaudit-elb-report.json) | Loki | ELB report rebuilt from Loki lines |
| [`deploy/helm/ctaudit/dashboards/ctaudit-waf-report.json`](../deploy/helm/ctaudit/dashboards/ctaudit-waf-report.json) | Loki | WAF report rebuilt from Loki lines |
| [`deploy/helm/ctaudit/dashboards/ctaudit-s3-report.json`](../deploy/helm/ctaudit/dashboards/ctaudit-s3-report.json) | Loki | S3 access log report rebuilt from Loki lines |
| [`deploy/helm/ctaudit/dashboards/ctaudit-vpc-report.json`](../deploy/helm/ctaudit/dashboards/ctaudit-vpc-report.json) | Loki | VPC Flow Logs report rebuilt from Loki lines |
| [`docs/grafana/ctaudit-serve-dashboard.json`](grafana/ctaudit-serve-dashboard.json) | Prometheus, Loki | Health and totals of `ctaudit serve` scanners |
| [`docs/grafana/ctaudit-dashboard.json`](grafana/ctaudit-dashboard.json) | Prometheus, Loki | One-shot runs that push to the Pushgateway |

Import any of them in Grafana (Dashboards, New, Import) and pick the data sources when asked; each dashboard has a `loki` data source variable, and the last two also have a `prometheus` one.

### Report dashboards

The five report dashboards in [`deploy/helm/ctaudit/dashboards/`](../deploy/helm/ctaudit/dashboards) rebuild the HTML reports from the Loki lines alone, with no Prometheus needed. Every panel has a description, shown by its (i) icon, that says what it counts. Most tables end with the newest 500 matching lines.

- **`ctaudit-cloudtrail-report.json`** (uid `ctaudit-cloudtrail-report`). Summary: event, write, and error totals, findings by severity, events by account (the legend carries each account's total), and findings by severity over time. Findings: by rule, actor, and account, and the finding lines. Activity: top principals, event names, services, error codes, source IPs, user agents, regions, and identity types. Matching events as rows. Variables: job, account, region, severity, principal and event name text filters, and Top N.
- **`ctaudit-elb-report.json`** (uid `ctaudit-elb-report`). Traffic: request, byte, 4xx, 5xx, latency, and load balancer totals. Health: gauges for the average target response time (orange from 0.5 s, red from 1 s), the 5xx rate (1% and 5%), and target connection errors, and a count of targets that returned a 5xx. Timeline: requests by ELB status class, target responses with connection errors, latency with 0.5 s and 1 s guides, the average latency of the slowest paths, and bar gauges for load balancer, method, and listener type. Target groups and timing: one row per target group and the slowest paths. Failing requests, driven by the `fail_status` variable (4xx and 5xx, 5xx only, or 4xx only): count and share, failing requests by status over time, by path, client IP, target, error reason, and load balancer, and the failing lines. Requests: ELB and target status, client IPs, hosts, paths, user agents, targets, action, TLS protocol and cipher, classifications. TLS connections: connection totals and tables from ALB connection logs. Matching requests as rows. Variables: job, load balancer, client IP and status regular expressions, failing status, and Top N.
- **`ctaudit-waf-report.json`** (uid `ctaudit-waf-report`). Summary: request, blocked, allowed, counted, and challenged totals, block rate, web ACL count, and requests by action over time. Findings. Blocking: terminating rules (non-ALLOW), rule groups, top blocked client IPs, blocked countries, and actions by inspection source. Clients: top client IPs, countries, JA4 fingerprints, user agents. Requests: hosts, URIs, methods, response codes. Matching requests as rows. Variables: job, web ACL, action, client IP, and Top N.
- **`ctaudit-s3-report.json`** (uid `ctaudit-s3-report`). Summary: request, error, denied, anonymous, and bytes sent totals, bucket count, and requests by status class over time. Findings. Access: operations, requesters, top remote IPs, denied by remote IP, error codes. Data: top keys, bytes sent by requester and by remote IP, requests by bucket. Security posture: TLS versions, auth types, signature versions, user agents. Matching requests as rows. Variables: job, bucket, status class, requester and remote IP regular expressions, and Top N.
- **`ctaudit-vpc-report.json`** (uid `ctaudit-vpc-report`). Summary: flow, rejected, accepted, byte, distinct source, and finding totals, and flows by action over time. Findings. Rejected traffic: top rejected sources, destination ports, and destinations. Traffic: top source/destination pairs by bytes, protocols, and network interfaces. Matching flows as rows. Variables: job, action, VPC ID, source and destination address regular expressions, and Top N. By default ctaudit ships only REJECT flows (`--emit-flows reject`), so the ACCEPT-driven panels stay empty unless the scanner runs with `--emit-flows all`.

The counts use the same rules as the HTML report: the principal is the ARN, else `invokedBy`, else `userName`, else `principalId`; numeric path segments become `{n}`; a write event is `readOnly=false`, or a missing `readOnly` and an event name that is not a read verb.

Two limits apply. First, the time picker selects Loki timestamps: request and event times for lines shipped with `--loki-time event` (the `serve` default), but scan runs for lines shipped with the one-shot default `--loki-time scan`. Second, tables that group by a high-cardinality field, such as client IP on a busy load balancer, can reach Loki's `max_query_series` limit (500 by default); a lower Top N does not help there, so narrow the filters or the time range.

**Shipping them with the Helm chart.** Set `grafanaDashboards.enabled: true` and the chart renders one ConfigMap, `<fullname>-dashboards`, that carries all five files and is labeled `grafana_dashboard: "1"` for the Grafana dashboard sidecar. Set `grafanaDashboards.namespace` when the sidecar watches a different namespace, and `grafanaDashboards.annotations` for a folder, for example `grafana_folder: Security`. The dashboards need `loki.url` set on the chart, or there are no lines to read. See [Kubernetes](kubernetes.md#grafana-dashboards).

### Serve dashboard

[`docs/grafana/ctaudit-serve-dashboard.json`](grafana/ctaudit-serve-dashboard.json) (uid `ctaudit-serve`) watches `ctaudit serve` scanners through the metrics Prometheus scrapes from `/metrics`, with Loki log panels alongside. Rows:

- Scans: minutes since the last clean tick, failed ticks and scan errors in the range, seen keys, scans by result, records read and matched, and scan duration
- CloudTrail: critical and high findings and write events in the range, findings by severity, and the finding lines
- Load balancers: requests by status class, mean latency, TLS handshake failures, bytes, and 5xx request lines
- S3 access logs: requests by status class, bytes sent, and denied request lines
- VPC Flow Logs: flows by action, bytes, and rejected flow lines

Variables: `prometheus` and `loki` data sources, `job` (from `label_values(ctaudit_scans_total, job)`), `subcommand`, and `lokijob`, the Loki `job` label (default `ctaudit`, the `--push-job` default).

### Pushgateway dashboard

[`docs/grafana/ctaudit-dashboard.json`](grafana/ctaudit-dashboard.json) (uid `ctaudit`) is for one-shot runs, for example from a cron job, that push to the Pushgateway with `--pushgateway` and to Loki with `--loki`. It reads the last-run gauges (`ctaudit_objects_scanned`, `ctaudit_findings`, `ctaudit_elb_requests`, and the rest). Rows:

- Runs: hours since the last clean run, scan errors, objects scanned, records matched, and scan duration
- CloudTrail: critical and high findings, write and error events, findings by severity, and the finding lines
- Load balancers: requests by status class, latency, bytes, TLS connections, and 5xx request lines

Variables: `prometheus` and `loki` data sources, `job` (default `ctaudit`), and `subcommand` (`cloudtrail`, `elb`). It has no WAF, S3, or VPC panels.
