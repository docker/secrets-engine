#syntax=docker/dockerfile:1

ARG GO_VERSION=latest
ARG OSXCROSS_VERSION=15.5

FROM --platform=${BUILDPLATFORM} tonistiigi/xx AS xx
# osxcross contains the MacOSX cross toolchain for xx
FROM --platform=${BUILDPLATFORM} crazymax/osxcross:${OSXCROSS_VERSION}-alpine AS osxcross

FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION}-alpine AS gobase
RUN apk add --no-cache findutils build-base git

FROM gobase AS linux-base
ARG TARGETARCH
ENV GOOS=linux
ENV GOARCH=${TARGETARCH}
COPY --link --from=xx / /
RUN apk add --no-cache clang lld
RUN xx-apk add musl-dev gcc
RUN xx-go --wrap

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
FROM ${TARGETOS}-base AS build-engine
ARG TARGETOS
ARG TARGETARCH
ARG ENGINE_BINARY
ENV CGO_ENABLED=1
WORKDIR /src
RUN mkdir /out
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=tmpfs,target=/go/src/ <<EOT
    set -euo pipefail
    EXT=""
    [ "$TARGETOS" = "windows" ] && EXT=".exe"
    go build -ldflags "-s -w" -o "/out/${ENGINE_BINARY}${EXT}" ./engine/daemon
EOT

FROM scratch AS package-engine
COPY --link --from=build-engine /out .
