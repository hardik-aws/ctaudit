BINARY := ctaudit
PKG    := ./cmd/ctaudit
IMAGE  ?= ctaudit
TAG    ?= $(shell git describe --tags --always --dirty)
CHART  := deploy/helm/ctaudit

.PHONY: build test vet fmt check clean image helm-lint

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BINARY) $(PKG)

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# check fails if any file is unformatted, then vets and tests. Use it in CI.
check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	go vet ./...
	go test -race -count=1 ./...

# image builds the container image. Pushing it is left to the user or CI.
image:
	docker build -t $(IMAGE):$(TAG) .

# helm-lint lints the chart and checks that the CI values render the
# expected objects. It skips when helm is not installed.
HELM_KINDS := Deployment=2 PrometheusRule=1 Secret=1 Service=2 ServiceAccount=1 ServiceMonitor=1
helm-lint:
	@if ! command -v helm >/dev/null 2>&1; then echo "helm not installed; skipping helm-lint"; exit 0; fi; \
	set -e; \
	helm lint $(CHART) -f $(CHART)/ci/test-values.yaml; \
	kinds="$$(helm template ctaudit-ci $(CHART) -f $(CHART)/ci/test-values.yaml | sed -n 's/^kind: //p' | sort | uniq -c | awk '{printf "%s%s=%s", sep, $$2, $$1; sep=" "}')"; \
	if [ "$$kinds" != "$(HELM_KINDS)" ]; then echo "helm template rendered: $$kinds"; echo "want: $(HELM_KINDS)"; exit 1; fi; \
	echo "helm template rendered: $$kinds"

clean:
	rm -f $(BINARY) ctaudit-report.html
