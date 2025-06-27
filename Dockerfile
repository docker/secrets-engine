#syntax=docker/dockerfile:1

ARG GO_VERSION=latest
ARG GOLANGCI_LINT_VERSION=latest

FROM --platform=${BUILDPLATFORM} golangci/golangci-lint:${GOLANGCI_LINT_VERSION}-alpine AS lint-base

FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION}-alpine AS base
WORKDIR /app
RUN apk add --no-cache git
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build



FROM base AS lint
COPY --from=lint-base /usr/bin/golangci-lint /usr/bin/golangci-lint
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/.cache/golangci-lint <<EOD
    set -e
    go mod tidy --diff
    (cd plugin && go mod tidy --diff)
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} golangci-lint --timeout 30m0s run ./...
EOD

FROM base AS do-format
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install golang.org/x/tools/cmd/goimports@latest
COPY . .
RUN goimports -local github.com/docker/secrets-engine -w .
RUN gofmt -s -w .

FROM scratch AS format
COPY --from=do-format /app .

FROM base AS proto-base
ARG BUF_VERSION
RUN --mount=target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/usr/local/bin go install github.com/bufbuild/buf/cmd/buf@${BUF_VERSION}

FROM proto-base AS proto-lint
RUN --mount=target=. \
    buf lint

FROM proto-base AS do-proto-generate
COPY . .
RUN buf generate

FROM scratch AS proto-generate
COPY --from=do-proto-generate /app .

FROM base AS build-nri-plugin
ARG TARGETOS
ARG TARGETARCH
ARG GO_LDFLAGS
ARG NRI_PLUGIN_BINARY
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags "-s -w ${GO_LDFLAGS}" -o /out/${NRI_PLUGIN_BINARY} ./cmd/nri-plugin

FROM scratch AS binary-nri-plugin-unix
ARG NRI_PLUGIN_BINARY
COPY --link --from=build-nri-plugin /out/${NRI_PLUGIN_BINARY} /
FROM binary-nri-plugin-unix AS binary-nri-plugin-darwin
FROM binary-nri-plugin-unix AS binary-nri-plugin-linux
FROM scratch AS binary-nri-plugin-windows
ARG NRI_PLUGIN_BINARY
COPY --link --from=build-nri-plugin /out/${NRI_PLUGIN_BINARY} /${NRI_PLUGIN_BINARY}.exe
FROM binary-nri-plugin-$TARGETOS AS binary-nri-plugin
FROM --platform=$BUILDPLATFORM alpine AS packager-nri-plugin
WORKDIR /nri-plugin
ARG NRI_PLUGIN_BINARY
RUN --mount=from=binary-nri-plugin mkdir -p /out && cp ${NRI_PLUGIN_BINARY}* /out/
FROM scratch AS package-nri-plugin
COPY --from=packager-nri-plugin /out .
