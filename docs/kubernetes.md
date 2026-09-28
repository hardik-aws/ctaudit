# Running ctaudit on Kubernetes

`ctaudit serve` turns any of the five subcommands into a long-running scanner. It rescans a rolling window on a fixed interval, keeps running totals as Prometheus counters on `/metrics`, serves the HTML report for the window on `/report`, and streams new matches to Loki. The Helm chart in [`deploy/helm/ctaudit`](../deploy/helm/ctaudit) runs one pod per scanner.

Related documents:

- [Terraform](terraform.md) creates the IRSA role and installs this chart.
- [Prometheus metrics](prometheus-metrics.md) lists every metric on `/metrics` and the alert rules.
- [Grafana and Loki](grafana.md) covers the dashboards and the Loki lines the scanners ship.

## Serve mode

```bash
./ctaudit serve cloudtrail --bucket org-trail --accounts 111122223333 --regions us-east-1 \
  --interval 15m --lookback 24h --loki http://loki-gateway.monitoring
./ctaudit serve elb --bucket alb-logs --accounts 111122223333 --regions us-east-1 --lb tiles
./ctaudit serve waf --bucket aws-waf-logs-example --accounts 111122223333 --regions us-east-1,cloudfront
./ctaudit serve s3 --bucket example-s3-access-logs --prefix logs/
./ctaudit serve vpc --bucket example-flow-logs --accounts 111122223333 --regions us-east-1
```

`serve` takes every flag of the named subcommand (see the [README](../README.md)) plus three of its own:

| Flag | Default | Meaning |
|---|---|---|
| `--interval` | `15m` | Time between the start of one scan and the next. Minimum `1m`. |
| `--lookback` | `24h` | Size of the rolling window. At least `--interval`, at most `720h`. |
| `--listen` | `:8080` | HTTP listen address for `/metrics`, `/healthz`, and `/report` |

`--since`, `--until`, `--html`, `--pdf`, `--pushgateway`, `--jsonl`, and `--fail-on` make no sense for a server and exit 2 if set. `--loki`, `--loki-tenant`, and `--push-job` work as in the one-shot commands; `--loki-time` defaults to `event` here. `--emit-flows` is allowed under `serve vpc` and works as it does one-shot. `serve elb` also accepts the `serve alb` alias.

**Incremental scans.** The first scan starts at once. Each scan covers `[now - lookback, now]`, lists the same day prefixes a one-shot run would, and skips every object key an earlier scan already read, so a steady-state scan fetches only newly delivered objects. S3 log objects are immutable, and late deliveries arrive as new keys. A scan commits only after its Loki push succeeds: if Loki fails, no key is marked as read and the next scan retries the whole batch, so lines may be duplicated but are never lost. Objects that fail to read stay unread and are retried on every scan. Scans never overlap.

Each tick ends with one of three results, counted in `ctaudit_scans_total{result}`:

- `ok`: every object was read and the Loki push succeeded. The tick commits.
- `partial`: some objects could not be read. The tick commits what it read; the unreadable objects are retried next tick.
- `failed`: a list error, a cancelled scan, or a failed Loki push. Nothing is committed.

**Restarts.** State lives in memory only. After a restart the first scan reads the whole lookback window again, Loki receives those lines a second time, and the counters start from zero, which `rate()` and `increase()` handle.

**Findings are per tick, not per window.** `serve cloudtrail`, `serve waf`, `serve s3`, and `serve vpc` run the findings rules (and, for WAF, `--block-threshold`; for S3, `--denied-threshold`, `--delete-threshold`, and `--egress-threshold`; for VPC, `--scan-ports`, `--sweep-hosts`, and `--egress-bytes`) once per tick, over only the records that tick newly saw. `ctaudit_findings_total`, `ctaudit_waf_findings_total`, `ctaudit_s3_findings_total`, and `ctaudit_vpc_findings_total` add up those per-tick results. A client IP that is blocked 60 times in one tick and 60 more in the next never crosses a `--block-threshold` of 100 in either tick's own findings, even though it would in a one-shot scan of the same window; the same goes for a VPC port scanner split across two ticks and `--scan-ports`. `/report`, by contrast, re-evaluates the rules once over every record from every merged tick still in the lookback, so its findings and severity can differ from what `/metrics` counted as ticks happened.

**Memory for `serve vpc`.** `serve vpc` keeps one bounded summary per committed tick within `--lookback`. For a busy internet-facing VPC, prefer `--fetch-workers 8` or fewer, and a shorter `--lookback` or a higher memory limit, over raising the caps.

### Endpoints

There is no authentication, so keep the Service ClusterIP.

| Path | Response |
|---|---|
| `/metrics` | Prometheus text format. Every family has a `subcommand` label. See [Prometheus metrics](prometheus-metrics.md#serve-mode-metrics). |
| `/report` | The usual self-contained HTML report for the whole window, merged from every committed scan in it. 503 until the first scan commits. |
| `/healthz` | `ok` while the process runs. It is not tied to scan success: a failing scan raises an alert, not a restart. |

SIGTERM (or SIGINT) stops the running scan, flushes Loki, and exits 0 after at most 10 seconds.

## Container image

Each release publishes a multi-arch image (`linux/amd64` and `linux/arm64`) to Docker Hub as `hardikaws/ctaudit:<version>`, for example `hardikaws/ctaudit:0.4.0`, and `hardikaws/ctaudit:latest`. See [Docker Hub overview](dockerhub.md).

To build your own, `make image` builds a static binary into `gcr.io/distroless/static-debian12:nonroot`, which runs as UID 65532. Set `IMAGE` and `TAG` to your registry, then push it yourself:

```bash
make image IMAGE=111122223333.dkr.ecr.us-east-1.amazonaws.com/ctaudit TAG=0.4.0
docker push 111122223333.dkr.ecr.us-east-1.amazonaws.com/ctaudit:0.4.0
```

## IAM role for service accounts

The pods get AWS credentials through IRSA. Create a role whose trust policy lets the chart's ServiceAccount assume it through the cluster's OIDC provider, and attach the [`iam/cloudtrail-audit-reader`](../iam/cloudtrail-audit-reader) policy. The ServiceAccount is named `<release>-ctaudit` by default, or just the release name when it already contains `ctaudit`, or `serviceAccount.name` when set. The [Terraform example](terraform.md) does all of this for you; by hand it looks like this:

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

## Helm chart

Each entry in `scanners` becomes one Deployment and one ClusterIP Service named `<fullname>-<scanner name>`. Each Deployment runs exactly one replica with the `Recreate` strategy, because two pods would send every line to Loki twice; do not scale them. The chart also renders the IRSA ServiceAccount, a Secret for Loki credentials when `loki.auth` is set, and, when enabled, a Prometheus Operator ServiceMonitor, a PrometheusRule with the serve alerts, and a ConfigMap with the Grafana report dashboards. [`deploy/helm/ctaudit/values.yaml`](../deploy/helm/ctaudit/values.yaml) documents every value.

### Values

| Value | Default | Meaning |
|---|---|---|
| `image.repository` | `""` | Required. `hardikaws/ctaudit` or your own registry |
| `image.tag` | chart `appVersion` | Image tag |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `serviceAccount.create` | `true` | Render the ServiceAccount |
| `serviceAccount.name` | `""` | Overrides the ServiceAccount name |
| `serviceAccount.roleArn` | `""` | IRSA role ARN; required when `create` is true |
| `aws.bucket`, `aws.bucketRegion`, `aws.accounts`, `aws.regions` | empty | Defaults shared by every scanner. Quote account IDs |
| `loki.url` | `""` | Loki base URL; empty disables Loki |
| `loki.tenant` | `""` | Sent as `X-Scope-OrgID` |
| `loki.existingSecret` | `""` | Secret with `CTAUDIT_LOKI_TOKEN`, or `CTAUDIT_LOKI_USER` and `CTAUDIT_LOKI_PASSWORD`, loaded with `envFrom` |
| `loki.auth` | `{}` | Or set `token`, or `user` and `password`, and the chart renders the Secret |
| `scanners[]` | one `cloudtrail` scanner | See below |
| `debug`, `logFormat` | `false`, `text` | Pass `--debug` and `--log-format` to every scanner |
| `resources` | 100m CPU, 256Mi request, 1Gi limit | Default container resources |
| `podAnnotations`, `nodeSelector`, `tolerations`, `affinity` | empty | Pod scheduling |
| `service.port` | `8080` | Service port |
| `serviceMonitor.enabled`, `.interval`, `.labels` | `false`, `60s`, `{}` | Prometheus Operator ServiceMonitor |
| `prometheusRule.enabled`, `.labels` | `false`, `{}` | Prometheus Operator PrometheusRule |
| `grafanaDashboards.enabled`, `.namespace`, `.labels`, `.annotations` | `false`, release namespace, `grafana_dashboard: "1"`, `{}` | ConfigMap of report dashboards for the Grafana sidecar |

### Scanners

Each `scanners[]` entry has:

| Field | Meaning |
|---|---|
| `name` | Unique scanner name; part of the Deployment and Service names |
| `subcommand` | `cloudtrail`, `elb`, `waf`, `s3`, or `vpc` |
| `interval`, `lookback` | Passed as `--interval` and `--lookback` (default `15m` and `24h`) |
| `bucket` | Overrides `aws.bucket` |
| `bucketRegion` | Overrides `aws.bucketRegion`; also sets `AWS_REGION` in the pod |
| `accounts` | Overrides `aws.accounts` |
| `regions` | Overrides `aws.regions` |
| `args` | Extra flags, e.g. `["--org-id", "o-abc123"]` |
| `resources` | Overrides the top-level `resources` |
| `debug`, `logFormat` | Override the top-level values |

Every scanner needs a bucket, accounts, and regions, from its own entry or from `aws`; the chart fails to render otherwise. For an `s3` scanner with the default simple layout, accounts and regions are ignored by ctaudit but must still be set; pass `["--prefix", "logs/"]` in `args`, and add `["--layout", "partitioned"]` for partitioned keys.

```yaml
# values-prod.yaml
image:
  repository: hardikaws/ctaudit
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

### ServiceMonitor and PrometheusRule

Both need the Prometheus Operator CRDs. The ServiceMonitor scrapes `/metrics` on every scanner Service and copies the `app.kubernetes.io/component` label (the scanner name) onto the series. The PrometheusRule carries the `ctaudit-serve` alert group, selecting this release's scanners with `job=~"<fullname>-.*"`; [`docs/grafana/ctaudit-serve-alerts.yaml`](grafana/ctaudit-serve-alerts.yaml) holds the same rules for Prometheus without the Operator. Both are described in [Prometheus metrics](prometheus-metrics.md#alert-rules). Set `labels` on each to match your Prometheus's selectors, for example `release: kube-prometheus-stack`.

### Grafana dashboards

`grafanaDashboards.enabled: true` adds a ConfigMap labeled `grafana_dashboard: "1"` that carries the five report dashboards from [`deploy/helm/ctaudit/dashboards/`](../deploy/helm/ctaudit/dashboards). Set `grafanaDashboards.namespace` when the Grafana sidecar watches a different namespace, and `grafanaDashboards.annotations` for a folder, for example `grafana_folder: Security`. See [Grafana and Loki](grafana.md).

### Security

The pods run as non-root (UID 65532) with a read-only root filesystem and a `RuntimeDefault` seccomp profile, drop every capability, and do not mount a Kubernetes API token. `make helm-lint` lints the chart and checks what it renders.
