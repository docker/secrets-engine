#syntax=docker/dockerfile:1

ARG GO_VERSION=latest

FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION}-alpine AS gobase
RUN apk add --no-cache findutils build-base git

FROM gobase AS build-mysecret
ARG TARGETOS
ARG TARGETARCH
ARG MYSECRET_BINARY
WORKDIR /src
RUN mkdir /out
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=tmpfs,target=/go/src/ <<EOT
    set -euo pipefail
    EXT=""
    [ "$TARGETOS" = "windows" ] && EXT=".exe"
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags "-s -w" -o "/out/${MYSECRET_BINARY}${EXT}" ./cmd/mysecret
EOT

FROM scratch AS package-mysecret
COPY --link --from=build-mysecret /out .
