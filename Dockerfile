#syntax=docker/dockerfile:1

ARG GO_VERSION=latest
ARG GOLANGCI_LINT_VERSION=v2.2.1
ARG OSXCROSS_VERSION=15.5

FROM --platform=${BUILDPLATFORM} golangci/golangci-lint:${GOLANGCI_LINT_VERSION}-alpine AS lint-base

FROM --platform=${BUILDPLATFORM} tonistiigi/xx AS xx
# osxcross contains the MacOSX cross toolchain for xx
FROM --platform=${BUILDPLATFORM} crazymax/osxcross:${OSXCROSS_VERSION}-alpine AS osxcross

FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION}-alpine AS gobase
RUN apk add --no-cache findutils build-base git

FROM gobase AS linux-base
ARG TARGETARCH
ENV GOOS=linux
ENV GOARCH=${TARGETARCH}

FROM gobase AS windows-base
ARG TARGETARCH
ENV GOOS=windows
ENV GOARCH=${TARGETARCH}

FROM gobase AS darwin-base
COPY --link --from=xx / /
COPY --link --from=osxcross /osxcross /osxcross
RUN apk add --no-cache clang lld musl-dev build-base findutils gcc
ARG TARGETARCH
ENV GOOS=darwin
ENV GOARCH=${TARGETARCH}
ENV PATH="/osxcross/bin:$PATH"
ENV LD_LIBRARY_PATH="/osxcross/lib:${LD_LIBRARY_PATH:-}"
ENV CC=o64-clang
ENV CXX=o64-clang++

ARG TARGETOS
FROM ${TARGETOS}-base AS lint
COPY --link --from=lint-base /usr/bin/golangci-lint /usr/bin/golangci-lint
WORKDIR /app
ENV CGO_ENABLED=1
RUN --mount=type=bind,target=.,ro \
    --mount=type=cache,target=/root/.cache <<EOT
    set -euo pipefail
    go mod tidy --diff
    (cd plugin && go mod tidy --diff)
    (cd store && go mod tidy --diff)
    golangci-lint run -v
EOT

FROM golang AS gofumpt
ARG GOFUMPT_VERSION=v0.8.0
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=tmpfs,target=/go/src/ \
    go install "mvdan.cc/gofumpt@${GOFUMPT_VERSION}" \
    && gofumpt --version

FROM golang AS goimports
ARG GOIMPORTS_VERSION=latest
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=tmpfs,target=/go/src/ \
    go install "golang.org/x/tools/cmd/goimports@${GOIMPORTS_VERSION}"

FROM ${TARGETOS}-base AS do-format
COPY --link --from=gofumpt /go/bin/gofumpt /go/bin/gofumpt
COPY --link --from=goimports /go/bin/goimports /go/bin/goimports
COPY --link --from=lint-base /usr/bin/golangci-lint /usr/bin/golangci-lint
WORKDIR /format
RUN mkdir -p /format/out
RUN --mount=type=bind,target=/src,rw <<EOT
    set -euo pipefail
    cd /src
    CGO_ENABLED=1 golangci-lint fmt -v
    ./scripts/copy-only-diff /format/out
EOT

FROM scratch AS format
COPY --from=do-format /format/out .

FROM gobase AS proto-base
ARG BUF_VERSION
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=tmpfs,target=/go/src/ \
    go install "github.com/bufbuild/buf/cmd/buf@${BUF_VERSION}"

FROM proto-base AS proto-lint
WORKDIR /app
RUN --mount=type=bind,target=. \
    buf lint

FROM proto-base AS do-proto-generate
WORKDIR /src
RUN mkdir -p /generate/out
RUN --mount=type=bind,target=.,rw <<EOT
    set -euo pipefail
    cd /src
    buf generate
    ./scripts/copy-only-diff /generate/out
EOT

FROM scratch AS proto-generate
COPY --from=do-proto-generate /generate/out .

FROM gobase AS build-nri-plugin
ARG TARGETOS
ARG TARGETARCH
ARG GO_LDFLAGS
ARG NRI_PLUGIN_BINARY
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=tmpfs,target=/go/src/ \
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
