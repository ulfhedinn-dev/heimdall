# Heimdall operator build + tooling.

GO            ?= go
GOFMT         ?= gofmt
BIN_DIR       := $(CURDIR)/bin
IMAGE_REPO    ?= ghcr.io/ulfhedinn-dev/heimdall
IMAGE_TAG     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PLATFORM      ?= linux/amd64
CONTROLLER_GEN ?= $(BIN_DIR)/controller-gen
GOLANGCI_LINT ?= $(BIN_DIR)/golangci-lint

.PHONY: all
all: fmt vet lint test build

.PHONY: fmt
fmt:
	$(GOFMT) -s -w ./api ./cmd ./internal

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: lint
lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run ./...

.PHONY: test
test:
	$(GO) test -race -count=1 ./...

.PHONY: build
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(IMAGE_TAG)" -o $(BIN_DIR)/heimdall ./cmd/operator

.PHONY: docker-build
docker-build:
	docker buildx build --platform $(PLATFORM) -t $(IMAGE_REPO):$(IMAGE_TAG) --load .

.PHONY: docker-push
docker-push:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMAGE_REPO):$(IMAGE_TAG) --push .

.PHONY: generate
generate: $(CONTROLLER_GEN)
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./api/..."

# Regenerate the chart's CRDs from the Go API types.
.PHONY: manifests
manifests: $(CONTROLLER_GEN)
	CONTROLLER_GEN=$(CONTROLLER_GEN) ./hack/gen-chart-crds.sh

# Fail if generated code or CRDs are out of date (used by CI).
.PHONY: verify-generated
verify-generated: generate manifests
	git diff --exit-code -- api chart/heimdall/templates/crds.yaml

# Run one real Trivy scan through Heimdall's scanner (needs network access).
.PHONY: smoke
smoke:
	$(GO) run ./hack/smoke $(or $(IMAGE),alpine:3.18.0)

# End-to-end test in a throwaway kind cluster (needs docker and kind).
.PHONY: e2e
e2e:
	./hack/e2e.sh

.PHONY: helm-lint
helm-lint:
	helm lint chart/heimdall

.PHONY: helm-template
helm-template:
	helm template heimdall chart/heimdall

$(CONTROLLER_GEN):
	GOBIN=$(BIN_DIR) $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.23.0

$(GOLANGCI_LINT):
	GOBIN=$(BIN_DIR) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
