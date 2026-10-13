# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.22 AS build
WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/heimdall ./cmd/operator

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /out/heimdall /heimdall
USER 65532:65532
ENTRYPOINT ["/heimdall"]
