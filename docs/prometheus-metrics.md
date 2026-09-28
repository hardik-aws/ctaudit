# Prometheus metrics

ctaudit exposes metrics in two ways:

- **Serve mode.** `ctaudit serve <subcommand>` serves `/metrics` for Prometheus to scrape. The values are counters that grow with every committed tick, so use `rate()` and `increase()`. See [Kubernetes](kubernetes.md).
- **One-shot runs.** With `--pushgateway URL`, a one-shot run pushes gauges that describe that run only, once, at the end. See [Grafana, Loki, and the Pushgateway](grafana.md#sending-data) for the flags and credentials.

The two sets have different names: serve counters end in `_total` (or `_sum` and `_count`), and the one-shot gauges do not.

## Serve-mode metrics

Every family carries a `subcommand` label (`cloudtrail`, `elb`, `waf`, `s3`, or `vpc`), and Prometheus adds its own target labels (`job`, `namespace`, `pod`, and, with the chart's ServiceMonitor, `app_kubernetes_io_component`). Every value of a labeled family (each result, severity, status class, or action) is present from the first scrape at zero, so `rate()` and `increase()` work immediately. Counters reset to zero when the pod restarts.

The object, record, and subcommand counters count only committed ticks (`ok` and `partial`); a `failed` tick adds nothing but a `ctaudit_scans_total{result="failed"}` increment.

### All subcommands

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_scans_total` | counter | `result` = `ok`, `partial`, `failed` | Scan ticks by result. `partial` means some objects were unreadable and will be retried; `failed` means a list error, a cancelled scan, or a failed Loki push, with nothing committed. Alert on `increase(...{result="failed"}[1h]) > 0` |
| `ctaudit_objects_scanned_total` | counter | | Log objects read by committed ticks. `rate()` shows how fast new log objects arrive |
| `ctaudit_records_read_total` | counter | | Records decoded by committed ticks |
| `ctaudit_records_matched_total` | counter | | Records that passed the filters in committed ticks. Compare with `records_read` to see how selective the filters are |
| `ctaudit_scan_errors_total` | counter | | Objects that could not be read. Usually missing `s3:GetObject` or `kms:Decrypt`, or an unsupported object format; the pod log names the keys |
| `ctaudit_last_scan_timestamp_seconds` | gauge | | Unix time the last tick finished, whatever its result. Absent until the first tick ends |
| `ctaudit_scan_duration_seconds` | gauge | | Wall time of the last tick. If it approaches `ctaudit_interval_seconds`, ticks are falling behind |
| `ctaudit_last_success_timestamp_seconds` | gauge | | Unix time of the last tick that committed without errors (`ok`). Absent until the first clean tick. `time() - this` is the staleness of the data |
| `ctaudit_seen_keys` | gauge | | Object keys remembered as already read. Grows with the lookback window and drives memory use |
| `ctaudit_lookback_seconds` | gauge | | Configured `--lookback` |
| `ctaudit_interval_seconds` | gauge | | Configured `--interval`. Used by the `CtauditNoRecentSuccess` alert |

### `serve cloudtrail`

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_findings_total` | counter | `severity` = `low`, `medium`, `high`, `critical` | Rule hits by severity, including hits past the findings cap. Evaluated per tick over newly read events only |
| `ctaudit_cloudtrail_write_events_total` | counter | | Matching events that were not read-only |
| `ctaudit_cloudtrail_error_events_total` | counter | | Matching events that returned an error code. A spike can mean probing or a broken deployment |

### `serve elb`

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_elb_requests_total` | counter | `status_class` = `2xx`, `3xx`, `4xx`, `5xx`, `other` | Matching requests by ELB status class. The 5xx share is `rate(...{status_class="5xx"}) / rate(...)` |
| `ctaudit_elb_received_bytes_total` | counter | | Bytes received from clients by matching requests |
| `ctaudit_elb_sent_bytes_total` | counter | | Bytes sent to clients by matching requests |
| `ctaudit_elb_latency_seconds_sum` | counter | | Sum of measurable request latency |
| `ctaudit_elb_latency_seconds_count` | counter | | Requests with a measurable latency. Mean latency is `rate(_sum) / rate(_count)`; requests with unknown latency are left out of both |
| `ctaudit_elb_conns_total` | counter | | Matching ALB connection log records |
| `ctaudit_elb_conns_tls_total` | counter | | Matching connections that negotiated TLS |
| `ctaudit_elb_tls_handshake_failed_total` | counter | | Matching connections whose TLS handshake failed |
| `ctaudit_elb_tls_handshake_seconds_sum` | counter | | Sum of measured TLS handshake time |
| `ctaudit_elb_tls_handshake_seconds_count` | counter | | Connections with a measured handshake time. Mean handshake time is `rate(_sum) / rate(_count)` |

### `serve waf`

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_waf_requests_total` | counter | `action` = `ALLOW`, `BLOCK`, `COUNT`, `CAPTCHA`, `CHALLENGE` | Matching requests by WAF action. Block rate is `rate(...{action="BLOCK"}) / rate(...)` |
| `ctaudit_waf_findings_total` | counter | `severity` = `low`, `medium`, `high`, `critical` | WAF findings raised per tick, by severity |

### `serve s3`

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_s3_requests_total` | counter | `status_class` = `2xx`, `3xx`, `4xx`, `5xx`, `other` | Matching requests by status class |
| `ctaudit_s3_findings_total` | counter | `severity` = `low`, `medium`, `high`, `critical` | S3 findings raised per tick, by severity |
| `ctaudit_s3_bytes_sent_total` | counter | | Bytes sent by matching requests. Watch `rate()` for unexpected egress |

### `serve vpc`

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_vpc_flows_total` | counter | `action` = `ACCEPT`, `REJECT` | Matching flows by action. A rising REJECT rate can mean scanning |
| `ctaudit_vpc_bytes_total` | counter | | Bytes in matching flows |
| `ctaudit_vpc_packets_total` | counter | | Packets in matching flows |
| `ctaudit_vpc_findings_total` | counter | `severity` = `low`, `medium`, `high`, `critical` | VPC findings raised per tick, by severity |

Findings counters are per tick: a threshold crossed only across two ticks does not count. See [Findings are per tick](kubernetes.md#serve-mode).

## Pushgateway metrics (one-shot runs)

A one-shot run with `--pushgateway` pushes once, at the end, to `<URL>/metrics/job/<push-job>/subcommand/<subcommand>`, so the subcommands never overwrite each other. The Pushgateway attaches the grouping labels `job` (the `--push-job` value, default `ctaudit`) and `subcommand` to every series. Every metric is a gauge that describes the last run only. Labeled families always carry every label value, with zeros, so no stale series survive from an earlier run.

### All subcommands

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_objects_scanned` | gauge | | Log objects read in the last run |
| `ctaudit_records_read` | gauge | | Records decoded in the last run |
| `ctaudit_records_matched` | gauge | | Records that passed the filters in the last run |
| `ctaudit_scan_errors` | gauge | | Objects that could not be read in the last run. Above 0 means the run was partial and exited 2 |
| `ctaudit_scan_duration_seconds` | gauge | | Wall time of the last scan |
| `ctaudit_last_run_timestamp_seconds` | gauge | | Unix time the last run finished |
| `ctaudit_last_success_timestamp_seconds` | gauge | | Unix time of the last complete run. Sent only when the scan had no errors and the Loki and JSONL output worked, so an earlier success stays in place after a failed run. Alert when it gets older than your schedule |

### `cloudtrail`

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_findings` | gauge | `severity` = `low`, `medium`, `high`, `critical` | Findings in the last run, by severity |
| `ctaudit_findings_dropped` | gauge | | Findings discarded past the findings cap. Above 0 means the report lists fewer findings than were raised |
| `ctaudit_cloudtrail_write_events` | gauge | | Matching mutating events |
| `ctaudit_cloudtrail_error_events` | gauge | | Matching events that returned an error code |

### `elb`

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_elb_requests` | gauge | `status_class` = `2xx`, `3xx`, `4xx`, `5xx`, `other` | Matching requests in the last run, by ELB status class |
| `ctaudit_elb_received_bytes` | gauge | | Bytes received from clients by matching requests |
| `ctaudit_elb_sent_bytes` | gauge | | Bytes sent to clients by matching requests |
| `ctaudit_elb_latency_avg_seconds` | gauge | | Mean total latency of matching requests |
| `ctaudit_elb_latency_max_seconds` | gauge | | Highest total latency of matching requests |
| `ctaudit_elb_conns` | gauge | | Matching ALB connection log records |
| `ctaudit_elb_conns_tls` | gauge | | Matching connections that negotiated TLS |
| `ctaudit_elb_tls_handshake_failed` | gauge | | Matching connections whose TLS handshake failed |
| `ctaudit_elb_tls_handshake_avg_seconds` | gauge | | Mean TLS handshake time |
| `ctaudit_elb_tls_handshake_max_seconds` | gauge | | Highest TLS handshake time |

### `waf`

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_waf_requests` | gauge | `action` = `ALLOW`, `BLOCK`, `COUNT`, `CAPTCHA`, `CHALLENGE` | Matching requests in the last run, by action |
| `ctaudit_waf_findings` | gauge | `severity` = `low`, `medium`, `high`, `critical` | Findings in the last run, by severity |
| `ctaudit_waf_web_acls` | gauge | | Web ACLs discovered and kept in the last run. 0 usually means a wrong `--regions` or `--web-acls` |

### `s3`

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_s3_requests` | gauge | `status_class` = `2xx`, `3xx`, `4xx`, `5xx`, `other` | Matching requests in the last run, by status class. Requests with no status count as `other` |
| `ctaudit_s3_findings` | gauge | `severity` = `low`, `medium`, `high`, `critical` | Findings in the last run, by severity |
| `ctaudit_s3_bytes_sent` | gauge | | Bytes sent by matching requests in the last run |

### `vpc`

| Metric | Type | Labels | Meaning and use |
|---|---|---|---|
| `ctaudit_vpc_flows` | gauge | `action` = `ACCEPT`, `REJECT` | Matching flows in the last run, by action |
| `ctaudit_vpc_bytes` | gauge | | Bytes in matching flows in the last run |
| `ctaudit_vpc_packets` | gauge | | Packets in matching flows in the last run |
| `ctaudit_vpc_findings` | gauge | `severity` = `low`, `medium`, `high`, `critical` | Findings in the last run, by severity |

## Alert rules

### Serve mode

The `ctaudit-serve` group is rendered by the chart's PrometheusRule ([`deploy/helm/ctaudit/templates/prometheusrule.yaml`](../deploy/helm/ctaudit/templates/prometheusrule.yaml), `prometheusRule.enabled: true`), selecting the release's scanners with `job=~"<fullname>-.*"`. The same rules for Prometheus without the Operator are in [`docs/grafana/ctaudit-serve-alerts.yaml`](grafana/ctaudit-serve-alerts.yaml), where the selector is `job=~".*ctaudit.*"`; load it through `rule_files`.

| Alert | Severity | Fires when | What to do |
|---|---|---|---|
| `CtauditCriticalFinding` | critical | `increase(ctaudit_findings_total{severity="critical"}[30m]) > 0` | A CRITICAL CloudTrail rule fired (root usage, CloudTrail tampering). Open `/report` on the scanner, or query Loki for `{kind="finding", severity="critical"}` |
| `CtauditHighFinding` | warning | `increase(ctaudit_findings_total{severity="high"}[30m]) > 0` | A HIGH CloudTrail rule fired. Review the finding in `/report` or Loki |
| `CtauditWAFCriticalFinding` | critical | `increase(ctaudit_waf_findings_total{severity="critical"}[30m]) > 0` | A client passed a COUNT-mode exploit rule and was allowed. Check the rule and consider switching it to BLOCK |
| `CtauditWAFHighFinding` | warning | `increase(ctaudit_waf_findings_total{severity="high"}[30m]) > 0` | An attacker was also allowed through, or a rate-based rule limited traffic. Review the findings |
| `CtauditS3CriticalFinding` | critical | `increase(ctaudit_s3_findings_total{severity="critical"}[30m]) > 0` | An anonymous write or delete succeeded. Check the bucket policy and ACLs at once |
| `CtauditS3HighFinding` | warning | `increase(ctaudit_s3_findings_total{severity="high"}[30m]) > 0` | Anonymous reads, a denied-request burst, or a mass delete. Review the findings |
| `CtauditVPCHighFinding` | warning | `increase(ctaudit_vpc_findings_total{severity="high"}[30m]) > 0` | A port scan or an internet-reachable sensitive port. Query Loki with `{kind="finding", subcommand="vpc"} \| json` |
| `CtauditScanErrors` | warning | `increase(ctaudit_scan_errors_total[1h]) > 0` | Objects failed to read; they are retried every tick. Check the pod log for the keys, and the IAM role for `s3:GetObject` and `kms:Decrypt` |
| `CtauditScanFailing` | warning | `increase(ctaudit_scans_total{result="failed"}[1h]) > 0` | A tick failed: a list error, a cancelled scan, or a failed Loki push. Nothing was committed and it will be retried; check the pod log and Loki |
| `CtauditNoRecentSuccess` | warning | `time() - ctaudit_last_success_timestamp_seconds > 3 * ctaudit_interval_seconds` for 10m | No clean tick for more than three intervals. Look at the two alerts above, or ticks that take longer than the interval |
| `CtauditNeverSucceeded` | warning | `up == 1` with no `ctaudit_last_success_timestamp_seconds`, for 2h | The pod is scraped but has never finished a clean tick. The 2h hold covers the first scan after a restart; after that, check permissions and Loki |
| `CtauditELB5xx` | warning | 5xx share of `ctaudit_elb_requests_total` over 15m above 5%, for 15m | The load balancers are returning errors. Open the ELB report dashboard or `/report` for the failing targets and paths |

`docs/grafana/ctaudit-serve-alerts.yaml` must stay in step with the chart's PrometheusRule.

### One-shot runs

[`docs/grafana/ctaudit-alerts.yaml`](grafana/ctaudit-alerts.yaml) holds the `ctaudit` group for the Pushgateway gauges. Its rules match on the `subcommand` label, because the Pushgateway's own `job` label replaces ctaudit's unless `honor_labels` is set.

| Alert | Severity | Fires when | What to do |
|---|---|---|---|
| `CtauditCriticalFinding` | critical | `ctaudit_findings{severity="critical"} > 0` | The last `cloudtrail` run reported a critical finding. Query Loki with `{job="ctaudit", kind="finding", severity="critical"} \| json` |
| `CtauditScanErrors` | warning | `ctaudit_scan_errors > 0` | The last run was partial. Check its stderr for the failing keys, and the permissions |
| `CtauditNoRecentSuccess` | warning | `time() - ctaudit_last_success_timestamp_seconds > 26 * 3600` | No clean run in 26 hours: the schedule stopped, or recent runs had scan errors or a failed Loki push |
| `CtauditNeverSucceeded` | warning | `absent(ctaudit_last_success_timestamp_seconds)` for 26h | No run has ever reported success to the Pushgateway |
