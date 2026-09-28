# ctaudit

`ctaudit` reads AWS logs straight from S3 and prints a report, then writes the same report to a single self-contained HTML file. It has five commands:

- `ctaudit cloudtrail` reads gzipped CloudTrail logs and reports security findings, forensic matches, and API volume.
- `ctaudit elb` (alias `ctaudit alb`) reads Elastic Load Balancing access logs from Application, Network, and Classic Load Balancers. It reports traffic, latency, status codes, clients, targets, and TLS usage, and lists the individual requests that match forensic filters.
- `ctaudit waf` reads AWS WAF traffic logs and reports request volume by action, blocking and rate-limit findings, and the terminating rules, clients, and requests behind them.
- `ctaudit s3` reads Amazon S3 server access logs and reports requests by operation, status, requester, and client, data egress, TLS and signature posture, and findings such as anonymous writes, denied-request bursts, mass deletes, and bucket policy changes.
- `ctaudit vpc` reads VPC Flow Logs (text format) and reports traffic, rejected flows, and network findings such as port scans and internet-reachable databases.
- `ctaudit serve cloudtrail|elb|waf|s3|vpc` runs any of the five as a long-running scanner with Prometheus metrics, for Kubernetes. See [Running on Kubernetes](#running-on-kubernetes).

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

## AWS WAF

```bash
./ctaudit waf --bucket aws-waf-logs-example --bucket-region us-east-1 \
  --accounts 111122223333 --regions us-east-1,cloudfront --since 2026-09-23 --until 2026-09-23 \
  --html waf-report.html
```

WAF traffic logs are delivered straight to S3, not through CloudTrail: `ctaudit waf` reads every object under `[<prefix>/]AWSLogs/[<org-id>/]<account>/WAFLogs/<region>/<web-acl>/YYYY/MM/DD/HH/mm/`. WAF delivers a gzipped file roughly every 5 minutes, one JSON record per line. Because the web ACL name sits before the date in the key, `ctaudit` first lists the web ACLs under each account and region, then scans their day prefixes; `--web-acls` narrows which ACLs are scanned. A CloudFront web ACL logs under the region element `cloudfront`, so scanning one needs `--regions cloudfront` (alongside any regional web ACLs' own regions). This prints the terminal summary and writes `waf-report.html`.

The report contains request volume by action (ALLOW, BLOCK, COUNT, CAPTCHA, CHALLENGE) and block rate; ranked tables for web ACLs, terminating rules, rule groups, client IPs, blocked client IPs, countries, blocked countries, hosts, normalized URIs, methods, user agents, inspection source, labels, COUNT-mode rules, JA4 fingerprints, and response codes; requests by hour (UTC); the security findings below; and, in the HTML report, a requests table with every kept field, capped at `--max-events`.

Only the `Host` and `User-Agent` headers are kept from each request; every other header, the query string (`args`), and any body are dropped at decode time and never reach a report or a sink.

### WAF flags

`--bucket`, `--accounts`, `--regions`, `--prefix`, `--since`, `--until`, `--top`, `--list-workers`, `--fetch-workers`, `--profile`, `--bucket-region`, `--debug`, and `--log-format` work as they do for CloudTrail. `--prefix` is the key prefix WAF writes under, before `AWSLogs/`.

| Flag | Default | Meaning |
|---|---|---|
| `--org-id` | | AWS Organizations ID segment in the key, e.g. `o-abc123`, when logs are delivered under an organization |
| `--web-acls` | | Comma-separated web ACL names; a log is scanned if its name contains any of them |
| `--action` | | Comma-separated actions: `ALLOW`, `BLOCK`, `COUNT`, `CAPTCHA`, `CHALLENGE` |
| `--client-ip` | | Client IP contains this text |
| `--country` | | Comma-separated two-letter country codes |
| `--rule` | | Terminating rule contains this text (case-insensitive) |
| `--uri` | | URI contains this text (case-insensitive) |
| `--host` | | Host header contains this text (case-insensitive) |
| `--block-threshold` | 100 | Block count at which a client IP becomes a finding |
| `--fail-on` | `critical` | Exit 1 when a finding is at or above `none`, `low`, `medium`, `high`, or `critical` |
| `--html` | `waf-report.html` | HTML report path. `""` skips it. Must not end in `.txt` |
| `--pdf` | | Also write a printable PDF report to this path. Must end in `.pdf` |
| `--max-events` | 200 | Matching requests kept for the requests table |

WAF files each object under the day and hour it was delivered, so requests from just before midnight on `--until` can land in the next day's prefix. Like the CloudTrail and ELB commands, `ctaudit waf` scans one extra day of prefixes and filters back to the exact window.

### WAF findings

| Rule | Severity | Fires on |
|---|---|---|
| `waf-exploit-allowed` | CRITICAL | A client IP had allowed requests that matched a COUNT-mode exploit rule (SQLi, XSS, and similar managed rules) |
| `waf-attacker-allowed` | HIGH | A client IP passed `--block-threshold` blocked requests and also had at least one allowed request |
| `waf-rate-limited` | HIGH | A RATE_BASED rule limited requests, reported per rule with its top client IPs |
| `waf-persistent-blocked-ip` | MEDIUM | A client IP passed `--block-threshold` blocked requests with no allowed requests |
| `waf-count-rule` | MEDIUM | A rule in COUNT mode matched requests; it would block them if switched to BLOCK |
| `waf-oversize` | MEDIUM | Requests had a body, headers, or cookies larger than WAF inspects (`oversizeFields`) |
| `waf-challenge-failures` | LOW | A client IP failed at least a tenth of `--block-threshold` CAPTCHA or challenge responses |

`waf-challenge-failures` counts `TOKEN_MISSING` responses too: WAF logs that response on every first CAPTCHA or challenge presentation, before the client has a chance to solve it, so a normal challenge flow always produces at least one.

`ctaudit waf` exits 1 when a finding is at or above `--fail-on` (default `critical`), 0 on a clean scan, and 2 on failure, the same as `cloudtrail`.

## Amazon S3 server access logs

```bash
./ctaudit s3 --bucket example-s3-access-logs --bucket-region us-east-1 \
  --prefix logs/ --since 2026-09-23 --until 2026-09-23 --html s3-report.html
```

S3 server access logging writes plain-text objects (not gzipped) into a target bucket under a target prefix, in one of two key formats, chosen per source bucket in its logging configuration. The default, simple layout writes `<prefix>YYYY-MM-DD-hh-mm-ss-<unique>`; `--accounts` and `--regions` are not needed for it and are ignored when set. The partitioned layout (`--layout partitioned`) writes `<prefix><source-account>/<source-region>/<source-bucket>/YYYY/MM/DD/...` and needs `--accounts` and `--regions`; `ctaudit` discovers the source buckets under each account and region with a delimiter listing and narrows them with `--source-buckets`. Unlike the other commands, `--prefix` is used verbatim, so `logs/` and `logs` are different prefixes; only a leading `/` is dropped. The objects are plain text, and S3 delivers them on a best-effort basis, usually within a few hours; a record can occasionally be missing.

The report contains request totals (requests, errors, denied, anonymous, bytes sent) and ranked tables (`s3RankedTables`: operations, requesters, remote IPs, status codes, error codes, denied by remote IP, source buckets, top keys, bytes sent by requester and by remote IP, TLS versions, auth types, signature versions, user agents), requests by hour (UTC), the security findings below, and, in the HTML report, a matching requests table capped at `--max-events`.

The request URI's and referer's query strings are dropped at decode time, because a presigned URL carries `X-Amz-Credential`, `X-Amz-Signature`, and security tokens there; `host_id`, `bucket_owner`, and `version_id` are dropped too. `--key-prefix` matches the object key as logged, which is URL-encoded.

### S3 flags

`--bucket`, `--accounts`, `--regions`, `--prefix`, `--since`, `--until`, `--top`, `--list-workers`, `--fetch-workers`, `--profile`, `--bucket-region`, `--debug`, and `--log-format` work as they do for CloudTrail. `--prefix` is the target prefix configured for server access logging on the source bucket, used verbatim.

| Flag | Default | Meaning |
|---|---|---|
| `--layout` | `simple` | Log object key format: `simple` or `partitioned` |
| `--accounts` | | Comma-separated 12-digit source account IDs (partitioned layout only) |
| `--regions` | | Comma-separated source bucket regions (partitioned layout only) |
| `--source-buckets` | | Comma-separated source bucket names; a record is kept if its bucket contains any of them (case-insensitive). For `partitioned` it also narrows discovery |
| `--operations` | | Comma-separated operations, matched as substrings, e.g. `REST.PUT.OBJECT` or `DELETE` |
| `--status` | | Comma-separated HTTP status codes or classes, e.g. `403,5xx` |
| `--requester` | | Requester contains this text (case-insensitive); `anonymous` matches unauthenticated requests |
| `--client-ip` | | Remote IP contains this text |
| `--key-prefix` | | Object key starts with this text (case-sensitive) |
| `--errors-only` | false | Only requests with status 400 or higher or an error code |
| `--denied-threshold` | 100 | Denied requests from one IP or requester that become a finding |
| `--delete-threshold` | 1000 | Objects deleted by one requester that become a finding |
| `--egress-threshold` | 10737418240 | Bytes sent to one requester or IP that become a finding (10 GiB) |
| `--fail-on` | `critical` | Exit 1 when a finding is at or above `none`, `low`, `medium`, `high`, or `critical` |
| `--html` | `s3-report.html` | HTML report path. `""` skips it. Must not end in `.txt` |
| `--pdf` | | Also write a printable PDF report to this path. Must end in `.pdf` |
| `--max-events` | 200 | Matching requests kept for the requests table |

S3 files each object under the time it was delivered, which trails the requests inside it, so requests from just before midnight on `--until` can land in the next day's objects. Like the other commands, `ctaudit s3` scans one extra day of prefixes and filters back to the exact window.

### S3 findings

| Rule | Severity | Fires on |
|---|---|---|
| `s3-anonymous-write` | CRITICAL | An anonymous request succeeded (2xx) with an object write, object delete, or multi-object delete. One finding per source bucket |
| `s3-anonymous-read` | HIGH | An anonymous object read succeeded. One finding per source bucket, with top IPs and keys |
| `s3-access-denied-burst` | HIGH | One remote IP, or one authenticated requester, has at least `--denied-threshold` denied requests |
| `s3-mass-delete` | HIGH | One principal deleted at least `--delete-threshold` objects |
| `s3-access-change` | MEDIUM | A successful bucket policy, ACL, or public access block change |
| `s3-large-egress` | MEDIUM | One authenticated requester, or one remote IP, was sent at least `--egress-threshold` bytes |
| `s3-weak-tls` | LOW | A principal used TLS below 1.2 |
| `s3-plain-http` | LOW | A principal sent REST requests over plain HTTP |
| `s3-sigv2` | LOW | A principal signed requests with Signature Version 2 |

`WEBSITE.*` requests are never counted as anonymous reads: the S3 website endpoint only ever serves anonymous requests by design. Counters keyed by an open-ended value (requester, remote IP, object key, and the per-principal rule inputs) hold at most 50,000 distinct keys; the rest are counted under `(other)`, which the rules ignore, so a scan of a busy public bucket cannot exhaust memory.

`ctaudit s3` exits 1 when a finding is at or above `--fail-on` (default `critical`), 0 on a clean scan, and 2 on failure, the same as `cloudtrail` and `waf`.

## VPC Flow Logs

Flow logs must be delivered to S3 in the default text format with the default partitioning: `AWSLogs/[<org-id>/]<account>/vpcflowlogs/<region>/YYYY/MM/DD/<account>_vpcflowlogs_<region>_<flow-log-id>_<YYYYMMDDTHHmmZ>_<hash>.log.gz`. Parquet objects fail the scan (exit 2), and a Hive-compatible prefix layout is reported as an error too; recreate the flow log with the text file format and without Hive-compatible prefixes. Both the default field list and a custom one work, because `ctaudit` reads the field names from each file's header line rather than assuming a fixed layout. The `--since`/`--until` window applies to each flow's `start` field.

```bash
./ctaudit vpc --bucket example-flow-logs --bucket-region us-east-1 \
  --accounts 111122223333 --regions us-east-1 --since 2026-09-23 --until 2026-09-23 \
  --action REJECT --dst-cidr 10.0.0.0/16
```

This prints the terminal summary and writes `vpc-report.html`.

### VPC flags

`--bucket`, `--accounts`, `--regions`, `--prefix`, `--since`, `--until`, `--top`, `--list-workers`, `--fetch-workers`, `--profile`, `--bucket-region`, `--debug`, and `--log-format` work as they do for CloudTrail. `--prefix` is the key prefix the flow log writes under, before `AWSLogs/`.

| Flag | Default | Meaning |
|---|---|---|
| `--org-id` | | AWS Organizations ID segment in the key, e.g. `o-abc123`, when logs are delivered under an organization |
| `--action` | | Comma-separated actions: `ACCEPT`, `REJECT` |
| `--src-cidr` | | Comma-separated CIDRs or addresses; matches `srcaddr` or `pkt-srcaddr` |
| `--dst-cidr` | | Comma-separated CIDRs or addresses; matches `dstaddr` or `pkt-dstaddr` |
| `--ports` | | Comma-separated ports and ranges, e.g. `22,8000-8100`; matches either end |
| `--protocol` | | Comma-separated protocol names (`tcp`, `udp`, `icmp`, `icmpv6`, `gre`, `esp`, `ah`, `sctp`) or numbers |
| `--interfaces` | | Comma-separated network interface IDs (`eni-...`) |
| `--vpcs` | | Comma-separated VPC IDs; flows from formats without `vpc-id` never match |
| `--scan-ports` | 25 | Distinct rejected destination ports that make a public source a port scanner |
| `--sweep-hosts` | 50 | Distinct private destinations that make a source a host sweep |
| `--egress-bytes` | `1GiB` | Bytes one private host must send to public addresses for a finding; plain bytes or `K`, `M`, `G`, `T` (binary) |
| `--emit-flows` | `reject` | Matching flows sent to `--loki` and `--jsonl`: `reject`, `all`, or `none` (findings are always sent) |
| `--fail-on` | `high` | Exit 1 when a finding is at or above `none`, `low`, `medium`, `high`, or `critical` |
| `--html` | `vpc-report.html` | HTML report path. `""` skips it. Must not end in `.txt` |
| `--pdf` | | Also write a printable PDF report to this path. Must end in `.pdf` |
| `--max-events` | 200 | Matching flows kept for the flows table |

`--src-cidr` and `--dst-cidr` also match `pkt-srcaddr`/`pkt-dstaddr`, and `--ports` matches either end (source or destination port).

Flow log objects are filed under the day they were delivered, so flows starting late on `--until` can land in the next day's prefix. Like the other commands, `ctaudit vpc` scans one extra day of prefixes and filters back to the exact window.

### VPC findings

| Rule | Severity | Fires on |
|---|---|---|
| `vpc-port-scan` | HIGH | A public source made rejected connection attempts to `--scan-ports` or more distinct destination ports |
| `vpc-sensitive-port-exposed` | HIGH | A private host accepted a connection to a sensitive port from a public source that looks like it started the flow |
| `vpc-host-sweep` | MEDIUM | A source started flows to `--sweep-hosts` or more distinct private addresses |
| `vpc-large-egress` | MEDIUM | A private host sent at least `--egress-bytes` in accepted flows it started to public addresses |
| `vpc-legacy-protocol` | LOW | An accepted flow used FTP, Telnet, or SMB |

Sensitive ports (SSH, RDP, MySQL, PostgreSQL, SQL Server, Redis, Elasticsearch, MongoDB, the Docker API, and memcached): `22, 3389, 3306, 5432, 1433, 6379, 9200, 27017, 2375, 11211`. Legacy ports (FTP, Telnet, SMB): `21, 23, 445`.

An address is classified as private (RFC 1918, `100.64.0.0/10`, link-local, loopback, `fc00::/7`, `fe80::/10`) or public. The source and destination addresses used for classification and for every rule prefer `pkt-srcaddr`/`pkt-dstaddr` over `srcaddr`/`dstaddr` when the format carries them. The host sweep, large egress, and sensitive-port-exposed rules count only flows whose source looks like the client: ICMP, a flow with unknown ports, or a source port above the destination port.

**Memory.** Every counter in the VPC summary is capped at 50,000 distinct keys, with the rest folded into `(other)`. The port-scan and host-sweep trackers follow at most 20,000 sources each. When a cap is reached, the report says findings may be incomplete. NODATA and SKIPDATA status rows are counted separately from flows; a SKIPDATA row triggers a warning, because flow log capture skipped records in that interval and totals undercount the real traffic. These caps apply per fetch worker during a one-shot scan, since each worker owns a full summary until the merge at the end; `serve vpc` instead keeps one bounded summary per committed tick within `--lookback`. For a busy internet-facing VPC, prefer `--fetch-workers 8` or fewer, and a shorter `--lookback` or a higher memory limit, over raising the caps.

`ctaudit vpc` exits 1 when a finding is at or above `--fail-on` (default `high`), 0 on a clean scan, and 2 on failure, the same as `cloudtrail` and `waf`.

## PDF report

All five subcommands take `--pdf <path>` to write a printable A4 report next to the HTML one. It holds the summary, the ELB health values, WAF action totals, or S3 or VPC traffic totals, timeline charts, target group and slowest path tables or WAF, S3, or VPC ranked tables, the hourly chart, and, for CloudTrail, WAF, S3, and VPC, every finding the report kept. It leaves out the matching requests, connections, events, and flows tables; use the HTML report for those. A PDF write failure exits 2.

## Prometheus and Loki

All five subcommands can push their results into an existing Prometheus and Grafana stack. The one-shot commands listen on no port: ctaudit pushes run metrics to a Prometheus Pushgateway and streams every matching record to the Loki push API, then exits. Both outputs are off unless you set their flags.

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

**Loki.** Every record that passes the filters is sent, uncapped by `--max-events`, and for `cloudtrail`, `waf`, `s3`, and `vpc` every finding follows at the end. Labels stay low-cardinality: `job`, `subcommand`, `kind` (`event`, `finding`, `request`, `conn`, or `flow`), plus `account` and `region` on CloudTrail events, `severity` and `account` on findings, `lb` on ELB lines, `acl` and `action` on WAF lines, `bucket` and `status_class` on S3 lines, and `action` and `vpc` on VPC flow lines. Each line is a JSON object with `kind`, `run_id`, and the record's fields. CloudTrail events keep CloudTrail's field names; findings, ELB lines, WAF lines, S3 lines, and VPC flow lines use snake_case. The line always carries the record time (`event_time` or CloudTrail's `eventTime`). With `--loki-time scan` each entry is stamped with the scan time, so Loki accepts any window. With `--loki-time event` each entry is stamped with its record time, so Grafana's time picker and over-time charts follow request, event, and flow times. Loki accepts a stream's entries only in order, within an out-of-order window of half `max_chunk_age` (1 hour by default), and refuses entries older than `reject_old_samples_max_age` (7 days by default). So in event mode ctaudit holds every line until the scan ends (at most 2,000,000; past that the run fails and asks for `--loki-time scan` or a shorter window), sorts each stream oldest first, and pushes one batch at a time. When Loki still refuses entries for their age, it keeps the rest of the push; ctaudit prints a warning with the count instead of failing, because a retry cannot make an entry younger. Keep event-mode windows inside the 7-day limit, or raise it in Loki. CloudTrail lines over 128 KiB drop `requestParameters`, `responseElements`, and `additionalEventData` and carry `"truncated": true`.

For `vpc`, `--emit-flows` controls which matching flows are sent: `reject` (the default) sends only REJECT flows; `all` sends every matching flow, which can produce millions of lines per hour on a busy VPC; `none` sends no flows. Findings are always sent regardless of `--emit-flows`.

```logql
{job="ctaudit", kind="finding", severity="critical"} | json | line_format "{{.rule}} {{.actor}} {{.title}}"
{job="ctaudit", subcommand="elb", kind="request"} | json | elb_status =~ "5.." | line_format "{{.client_ip}} {{.method}} {{.url}}"
{job="ctaudit", subcommand="waf", kind="request"} | json | action = "BLOCK" | line_format "{{.client_ip}} {{.rule}} {{.uri}}"
{job="ctaudit", subcommand="s3", kind="request", status_class="4xx"} | json | status = "403" | line_format "{{.remote_ip}} {{.requester}} {{.key}}"
{job="ctaudit", subcommand="vpc", kind="flow", action="REJECT"} | json | line_format "{{.source}} -> {{.destination}}:{{.dst_port}}"
{job="ctaudit", kind="event"} | json | userIdentity_type = "Root"
```

**Pushgateway.** Metrics are pushed once per run to `/metrics/job/<job>/subcommand/<cloudtrail|elb|waf|s3|vpc>`, so the subcommands never overwrite each other. Every run sends `ctaudit_objects_scanned`, `ctaudit_records_read`, `ctaudit_records_matched`, `ctaudit_scan_errors`, `ctaudit_scan_duration_seconds`, and `ctaudit_last_run_timestamp_seconds`. `ctaudit_last_success_timestamp_seconds` is sent only when the scan had no errors and the Loki and JSONL output worked, so an earlier success stays in place after a failed run. `cloudtrail` adds `ctaudit_findings{severity}`, `ctaudit_findings_dropped`, `ctaudit_cloudtrail_write_events`, and `ctaudit_cloudtrail_error_events`. `elb` adds `ctaudit_elb_requests{status_class}`, byte and latency gauges, and TLS connection gauges. `waf` adds `ctaudit_waf_requests{action}`, `ctaudit_waf_findings{severity}`, and `ctaudit_waf_web_acls`. `s3` adds `ctaudit_s3_requests{status_class}`, `ctaudit_s3_findings{severity}`, and `ctaudit_s3_bytes_sent`. `vpc` adds `ctaudit_vpc_flows{action}`, `ctaudit_vpc_bytes`, `ctaudit_vpc_packets`, and `ctaudit_vpc_findings{severity}`. Labeled families always carry every label value, with zeros, so no stale series survive.

A bad URL, job name, or credential variable exits 2 before any S3 call. A failed Loki or Pushgateway push also exits 2, after the reports are written. `docs/grafana/` holds an example dashboard and Prometheus alert rules.

**Report dashboards.** [`deploy/helm/ctaudit/dashboards/`](deploy/helm/ctaudit/dashboards) holds five Grafana dashboards that rebuild the HTML reports from the Loki lines alone, with no Prometheus needed:

- `ctaudit-elb-report.json` (uid `ctaudit-elb-report`) shows each piece of information once. The Traffic row has the request, byte, 4xx, 5xx, latency, and load balancer totals. A Health row has gauges for the average target response time (orange from 0.5 s, red from 1 s), the 5xx rate (1% and 5%), and target connection errors, and a count of targets that returned a 5xx. A Timeline row charts requests by ELB status class, target responses with connection errors, latency with dashed 0.5 s and 1 s guides, and the average latency of the five slowest paths, with pies for load balancer, method, and listener type. A Target groups and timing row has one table per target group (requests, target 2xx, 4xx, and 5xx, ELB 5xx, connection errors, targets, and average and maximum target time) and the slowest paths. A Failing requests section, driven by the `Failing status` variable (4xx and 5xx, 5xx only, or 4xx only), shows the failing count and share, failing requests by status over time, by path, client IP, target, error reason, and load balancer, and the failing request lines with their error reason and trace ID. The Requests row has the remaining request tables (ELB and target status, client IPs, hosts, normalized paths, user agents, targets, action, TLS protocol and cipher, classifications). The TLS connections row has the connection totals and tables that the request log does not carry: connections per load balancer, listener and TLS, key exchange, verify status, failed 443 handshakes by client IP, and incoming TLS alerts. It ends with the matching requests and connections as rows.
- `ctaudit-cloudtrail-report.json` (uid `ctaudit-cloudtrail-report`) shows the event, write, and error totals and the findings by severity, rule, actor, and account. Events by account is a chart whose legend carries each account's total. It has the principal, event name, service, error code, source IP, region, and identity type tables, and the matching findings and events as rows.
- `ctaudit-waf-report.json` (uid `ctaudit-waf-report`) has a Summary row with the request, blocked, allowed, counted, challenged, and block rate stats, the web ACL count, and requests by action over time. A Findings row lists the security findings by time, severity, rule, title, actor, and detail. A Blocking row, filtered to non-ALLOW actions where noted, has terminating rules, rule groups, the top blocked client IPs, blocked countries, and a pie of actions by inspection source. A Clients row has the top client IPs, countries, JA4 fingerprints, and user agents. A Requests row has hosts, normalized URIs, methods, and response codes. It ends with the matching requests as rows.
- `ctaudit-s3-report.json` (uid `ctaudit-s3-report`) has a Summary row with the request, error, denied, anonymous, and bytes sent stats, the source bucket count, and requests by status class over time. A Findings row lists the security findings by time, severity, rule, title, actor, and detail. An Access row has operations, requesters, top remote IPs, denied by remote IP, and error codes. A Data row has the top keys, bytes sent by requester and by remote IP, and requests by bucket. A Security posture row has TLS versions, auth types, signature versions, and user agents. It ends with the matching requests as rows.
- `ctaudit-vpc-report.json` (uid `ctaudit-vpc-report`) has a Summary row with the flow, rejected, accepted, byte, distinct source, and finding stats, and flows by action over time. A Findings row lists the security findings by time, severity, rule, title, actor, and detail. A Rejected traffic row has the top rejected sources, destination ports, and destinations. A Traffic row has the top source/destination pairs by bytes, a bar gauge of protocols, and the top network interfaces. It ends with the matching flows as rows. By default ctaudit ships only REJECT flows (`--emit-flows reject`), so its ACCEPT-driven panels stay empty unless the scanner runs with `--emit-flows all`; findings are always sent.

All five take a `loki` data source variable and filter on job, load balancer, web ACL, bucket, or account and region, and regular expressions for client IP and ELB status, or action, or principal and event name, or requester and remote IP; the VPC dashboard instead filters on action, VPC ID, and source/destination address regular expressions. `Top N` sets the table length. Every panel has a description, shown by its (i) icon, that says what it counts. The counts use the same rules as the HTML report: the principal is the ARN, else `invokedBy`, else `userName`, else `principalId`; numeric path segments become `{n}`; a write event is `readOnly=false`, or a missing `readOnly` and an event name that is not a read verb. Two limits apply. The time picker selects Loki timestamps: request and event times for lines shipped with `--loki-time event` (the `serve` default), but scan runs for lines shipped with the one-shot default `--loki-time scan`, whose over-time charts show when lines were shipped. Event-time lines carry no scan time, so shipping the same window twice in event mode doubles every count; give a re-run its own `--push-job`. Tables that group by a high-cardinality field, such as client IP on a busy load balancer, can reach Loki's `max_query_series` limit (500 by default); lower `Top N` does not help there, so narrow the filters or the time range. Import the files in Grafana, or set `grafanaDashboards.enabled: true` in the chart to ship them as a ConfigMap for the Grafana dashboard sidecar.

## Debug logging

`--debug`, or `CTAUDIT_DEBUG=1` in the environment, makes `cloudtrail`, `elb`, `waf`, `s3`, `vpc`, and `serve` log what they do to stderr. The reports on stdout and in files are unchanged. `--log-format json` writes one JSON object per line for log collectors; the default is `text` (`key=value`).

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

`ctaudit serve` turns any of the five subcommands into a long-running scanner for Kubernetes. It rescans a rolling window on a fixed interval, keeps running totals as Prometheus counters on `/metrics`, and streams new matches to Loki. The Helm chart in [`deploy/helm/ctaudit`](deploy/helm/ctaudit) runs one pod per scanner.

```bash
./ctaudit serve cloudtrail --bucket org-trail --accounts 111122223333 --regions us-east-1 \
  --interval 15m --lookback 24h --loki http://loki-gateway.monitoring
./ctaudit serve elb --bucket alb-logs --accounts 111122223333 --regions us-east-1 --lb tiles
./ctaudit serve waf --bucket aws-waf-logs-example --accounts 111122223333 --regions us-east-1,cloudfront
./ctaudit serve s3 --bucket example-s3-access-logs --prefix logs/
./ctaudit serve vpc --bucket example-flow-logs --accounts 111122223333 --regions us-east-1
```

`serve` takes every flag of the named subcommand plus three of its own:

| Flag | Default | Meaning |
|---|---|---|
| `--interval` | `15m` | Time between the start of one scan and the next. Minimum `1m`. |
| `--lookback` | `24h` | Size of the rolling window. At least `--interval`, at most `720h`. |
| `--listen` | `:8080` | HTTP listen address |

`--since`, `--until`, `--html`, `--pdf`, `--pushgateway`, `--jsonl`, and `--fail-on` make no sense for a server and exit 2 if set. `--loki`, `--loki-tenant`, and `--push-job` work as in the one-shot commands; `--loki-time` defaults to `event` here. `--emit-flows` is allowed under `serve vpc` and works as it does one-shot.

**Incremental scans.** The first scan starts at once. Each scan covers `[now - lookback, now]`, lists the same day prefixes a one-shot run would, and skips every object key an earlier scan already read, so a steady-state scan fetches only newly delivered objects. S3 log objects are immutable, and late deliveries arrive as new keys. A scan commits only after its Loki push succeeds: if Loki fails, no key is marked as read and the next scan retries the whole batch, so lines may be duplicated but are never lost. Objects that fail to read are retried on every scan. Scans never overlap.

**Restarts.** State lives in memory only. After a restart the first scan reads the whole lookback window again, Loki receives those lines a second time, and the counters start from zero, which `rate()` and `increase()` handle.

**Endpoints.** There is no authentication, so keep the Service ClusterIP.

| Path | Response |
|---|---|
| `/metrics` | Prometheus text: `ctaudit_scans_total{result}` (`ok`, `partial`, `failed`), object, record, and error counters, `ctaudit_findings_total{severity}`, `ctaudit_elb_requests_total{status_class}`, latency and TLS counters, `ctaudit_waf_requests_total{action}`, `ctaudit_waf_findings_total{severity}`, `ctaudit_s3_requests_total{status_class}`, `ctaudit_s3_findings_total{severity}`, `ctaudit_s3_bytes_sent_total`, `ctaudit_vpc_flows_total{action}`, `ctaudit_vpc_bytes_total`, `ctaudit_vpc_packets_total`, `ctaudit_vpc_findings_total{severity}`, `ctaudit_last_success_timestamp_seconds`, and `ctaudit_seen_keys`. Every family has a `subcommand` label. |
| `/report` | The usual self-contained HTML report for the whole window, merged from every scan in it. 503 until the first scan commits. |
| `/healthz` | `ok` while the process runs. It is not tied to scan success: a failing scan raises an alert, not a restart. |

SIGTERM stops the running scan, flushes Loki, and exits 0 after at most 10 seconds.

**Findings are per tick, not per window.** `serve cloudtrail`, `serve waf`, `serve s3`, and `serve vpc` run the findings rules (and, for WAF, `--block-threshold`; for S3, `--denied-threshold`, `--delete-threshold`, and `--egress-threshold`) once per tick, over only the records that tick newly saw, and `ctaudit_findings_total` / `ctaudit_waf_findings_total` / `ctaudit_s3_findings_total` / `ctaudit_vpc_findings_total` add up those per-tick results. A client IP that is blocked 60 times in one tick and 60 more in the next never crosses a `--block-threshold` of 100 in either tick's own findings, even though it would in a one-shot scan of the same window; the same goes for a VPC port scanner split across two ticks and `--scan-ports`. `/report`, by contrast, re-evaluates the rules once over every record from every merged tick still in the lookback, so its findings and severity can differ from what `/metrics` counted as ticks happened.

### Image

`make image` builds a static binary into `gcr.io/distroless/static-debian12:nonroot`, which runs as UID 65532. Set `IMAGE` and `TAG` to your registry, then push it yourself:

```bash
make image IMAGE=111122223333.dkr.ecr.us-east-1.amazonaws.com/ctaudit TAG=0.4.0
docker push 111122223333.dkr.ecr.us-east-1.amazonaws.com/ctaudit:0.4.0
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
  tag: "0.4.0"
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

The pods run as non-root with a read-only root filesystem, drop every capability, and do not mount a Kubernetes API token. `make helm-lint` lints the chart and checks what it renders. `grafanaDashboards.enabled: true` adds a ConfigMap labeled `grafana_dashboard: "1"` that carries the five report dashboards; set `grafanaDashboards.namespace` when the Grafana sidecar watches a different namespace, and `grafanaDashboards.annotations` for a folder, for example `grafana_folder: Security`. `docs/grafana/ctaudit-serve-dashboard.json` and `docs/grafana/ctaudit-serve-alerts.yaml` are the serve-mode dashboard and alert rules; the alert rules are the same ones the chart's PrometheusRule carries.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed; for `cloudtrail`, `waf`, `s3`, and `vpc`, no findings at or above `--fail-on` |
| 1 | `cloudtrail`, `waf`, `s3`, and `vpc` only: scan completed; findings at or above `--fail-on` (default `high` for `vpc`) exist |
| 2 | Scan failed: missing command, bad flags, AWS error, unreadable objects (a Parquet object or a Hive-partitioned layout for `vpc`), or a failed Loki or Pushgateway push |

Unreadable objects return 2 even when findings exist, because the report may be incomplete. A CI gate must not pass on a partial scan.

## IAM

`ctaudit` is read-only. It needs `s3:ListBucket` on the log bucket (restricted to the `AWSLogs/` prefix) and `s3:GetObject` on the log objects. It also needs `kms:Decrypt` when the trail uses SSE-KMS. The `elb` command needs the same two S3 permissions on the access log bucket. ELB access logs support only SSE-S3 encryption, so it never needs KMS. The `waf` command needs the same `s3:ListBucket` and `s3:GetObject` on the WAF log bucket; the reader policy must include that bucket too, and no extra permission is needed for the delimiter listing `ctaudit waf` uses to discover web ACL names. The `s3` command needs `s3:ListBucket` on the target bucket, scoped to the target prefix rather than `AWSLogs/`, and `s3:GetObject` on the target bucket; the Terraform reader module in [`iam/cloudtrail-audit-reader`](iam/cloudtrail-audit-reader) scopes listing to `AWSLogs/`, so grant the S3 access log bucket its own policy statement, or a separate module instance, for the target prefix. The `vpc` command needs only `s3:ListBucket` and `s3:GetObject` on the flow log bucket: flow logs use SSE-S3 encryption by default, so add `kms:Decrypt` only when the flow log is configured with an SSE-KMS bucket. It never writes to the bucket or changes any AWS resource.

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
