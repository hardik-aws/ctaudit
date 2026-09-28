# ctaudit

`ctaudit` reads AWS logs straight from S3 and writes a terminal report, a single self-contained HTML report, and an optional PDF report. It runs everything in-process with read-only S3 access: no Athena, no Glue, no other query service. It can also run as a long-running scanner with Prometheus metrics and Loki output, for Kubernetes.

Source, full documentation, and the Helm chart: https://github.com/hardik-aws/ctaudit

## Subcommands

| Subcommand | Reads | You get |
|---|---|---|
| `cloudtrail` | CloudTrail logs | Security findings (root usage, CloudTrail tampering, console logins without MFA, open security groups, and more), forensic matches, API volume |
| `elb` (alias `alb`) | ALB, NLB, and Classic access logs, ALB connection logs | Traffic, latency, status codes, clients, targets, TLS usage, matching requests |
| `waf` | AWS WAF logs | Requests by action, blocking and rate-limit findings, terminating rules and clients |
| `s3` | S3 server access logs | Requests by operation, status, and requester, egress, TLS and signature posture, findings such as anonymous writes and mass deletes |
| `vpc` | VPC Flow Logs (text format) | Traffic, rejected flows, findings such as port scans and internet-reachable databases |
| `serve <subcommand>` | any of the above | Rolling rescans with Prometheus metrics on `/metrics`, the HTML report on `/report`, and new matches streamed to Loki |

## Tags

- `<version>`, for example `0.4.0`: one per release, matching the GitHub release `v<version>`. Pin this in production.
- `latest`: the most recent release.
- `<version>-amd64` and `<version>-arm64`: the single-architecture images behind the multi-arch tag.

Every image is multi-arch for `linux/amd64` and `linux/arm64`, built on `gcr.io/distroless/static-debian12:nonroot`: a static binary, a CA bundle, no shell, running as UID 65532. The entrypoint is `/ctaudit`, so the container arguments are the ctaudit command line. Port 8080 is exposed for serve mode.

## One-shot scan

The container needs AWS credentials with `s3:ListBucket` and `s3:GetObject` on the log bucket (and `kms:Decrypt` for SSE-KMS CloudTrail logs), and a writable directory for the reports.

Pass credentials through the environment, for example exported from an AWS CLI profile:

```bash
eval "$(aws configure export-credentials --profile my-profile --format env)"
mkdir -p reports
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_REGION=us-east-1 \
  -v "$PWD/reports:/reports" \
  hardikaws/ctaudit:0.4.0 cloudtrail \
    --bucket org-cloudtrail-logs --bucket-region us-east-1 \
    --accounts 111122223333 --regions us-east-1 \
    --since 2026-09-21 --until 2026-09-27 \
    --html /reports/ctaudit-report.html --pdf /reports/ctaudit-report.pdf
```

The terminal report goes to stdout and the HTML and PDF reports land in `./reports`. `--user` makes the files owned by you; without it, the mounted directory must be writable by UID 65532.

Or mount your AWS config and pick a profile. The image's home directory is `/home/nonroot`:

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" -e HOME=/home/nonroot \
  -v "$HOME/.aws:/home/nonroot/.aws" \
  -v "$PWD/reports:/reports" \
  hardikaws/ctaudit:0.4.0 elb --profile my-profile \
    --bucket example-alb-logs --bucket-region us-east-1 \
    --accounts 111122223333 --regions us-east-1 \
    --since 2026-09-23 --until 2026-09-23 \
    --html /reports/elb-report.html
```

For AWS SSO profiles, run `aws sso login --profile my-profile` on the host first. The SDK caches SSO tokens under `~/.aws`, so leave that mount writable.

The other subcommands work the same way:

```bash
docker run --rm ... hardikaws/ctaudit:0.4.0 waf --bucket aws-waf-logs-example --accounts 111122223333 \
  --regions us-east-1,cloudfront --html /reports/waf-report.html --fail-on high
docker run --rm ... hardikaws/ctaudit:0.4.0 s3 --bucket example-s3-access-logs --prefix logs/ \
  --html /reports/s3-report.html
docker run --rm ... hardikaws/ctaudit:0.4.0 vpc --bucket example-flow-logs --accounts 111122223333 \
  --regions us-east-1 --action REJECT --html /reports/vpc-report.html
```

Exit codes: 0 when the scan completed cleanly, 1 when `cloudtrail`, `waf`, `s3`, or `vpc` found something at or above `--fail-on`, and 2 on any failure, including an unreadable object, so a partial scan never passes a CI gate.

## Serve mode

```bash
docker run -d --name ctaudit-cloudtrail -p 8080:8080 \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_REGION=us-east-1 \
  -e CTAUDIT_LOKI_TOKEN \
  hardikaws/ctaudit:0.4.0 serve cloudtrail \
    --bucket org-cloudtrail-logs --bucket-region us-east-1 \
    --accounts 111122223333 --regions us-east-1 \
    --interval 15m --lookback 24h \
    --loki http://loki.example.internal:3100
```

Then open `http://localhost:8080/report` for the HTML report over the window, `http://localhost:8080/metrics` for Prometheus, and `http://localhost:8080/healthz` for a liveness check. The endpoints have no authentication, so do not publish the port beyond a trusted network. Temporary credentials expire, so a long-running container is better served by an instance or pod role. Run exactly one container per scanner: two would send every Loki line twice.

On Kubernetes, use the Helm chart in the repository, which runs one pod per scanner with IRSA credentials: https://github.com/hardik-aws/ctaudit/blob/main/docs/kubernetes.md

## Environment variables

| Variable | Meaning |
|---|---|
| `CTAUDIT_LOKI_USER`, `CTAUDIT_LOKI_PASSWORD` | Basic auth for `--loki` |
| `CTAUDIT_LOKI_TOKEN` | Bearer token for `--loki` |
| `CTAUDIT_PUSHGATEWAY_USER`, `CTAUDIT_PUSHGATEWAY_PASSWORD` | Basic auth for `--pushgateway` |
| `CTAUDIT_PUSHGATEWAY_TOKEN` | Bearer token for `--pushgateway` |
| `CTAUDIT_DEBUG` | `1` turns on debug logging to stderr, like `--debug` |
| `AWS_*` | The standard AWS SDK variables: credentials, `AWS_REGION`, `AWS_PROFILE` |

Loki and Pushgateway credentials are read only from the environment, never from flags. Set a user and password or a token for each target, not both.

## Documentation

- README, with every flag and finding rule: https://github.com/hardik-aws/ctaudit#readme
- Kubernetes, serve mode, and the Helm chart: https://github.com/hardik-aws/ctaudit/blob/main/docs/kubernetes.md
- Terraform (IRSA role and least-privilege reader policy): https://github.com/hardik-aws/ctaudit/blob/main/docs/terraform.md
- Grafana dashboards and Loki: https://github.com/hardik-aws/ctaudit/blob/main/docs/grafana.md
- Prometheus metrics and alert rules: https://github.com/hardik-aws/ctaudit/blob/main/docs/prometheus-metrics.md
- Releases and binaries: https://github.com/hardik-aws/ctaudit/releases
