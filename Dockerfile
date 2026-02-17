#syntax=docker/dockerfile:1

# Copyright 2025-2026 Docker, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
ENV CGO_ENABLED=1
ENV GOPRIVATE=github.com/docker/*
COPY --link --from=lint-base /usr/bin/golangci-lint /usr/bin/golangci-lint
RUN apk add --no-cache openssh-client
WORKDIR /app
RUN mkdir -p -m 0700 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
RUN --mount=type=bind,target=.,ro \
    --mount=type=secret,id=GH_TOKEN,env=GH_TOKEN \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=ssh <<EOT
    set -euo pipefail

    # Avoid interactive git prompts in CI
    export GIT_TERMINAL_PROMPT=0

    # If no token, prefer SSH for GitHub; if token exists, we’ll override below
    git config --global url."ssh://git@github.com/".insteadOf "https://github.com/"

    # fallback for CI environments without ssh keys
    if [ -n "$GH_TOKEN" ]; then
        rm -f ~/.gitconfig
        git config --global user.email "106345742+cloud-platform-ci[bot]@users.noreply.github.com"
        git config --global user.name "cloud-platform-ci[bot]"
        git config --global url."https://x-access-token:${GH_TOKEN}@github.com".insteadOf "https://github.com"
        git config --global --add url."https://x-access-token:${GH_TOKEN}@github.com".insteadOf "ssh://git@github.com"
        git config --global --add url."https://x-access-token:${GH_TOKEN}@github.com/".insteadOf "git@github.com:"
    fi

    for dir in $(go list -f '{{.Dir}}' -m); do
      (cd "$dir" && go mod tidy --diff)
    done
EOT
RUN --mount=type=bind,target=.,ro \
    --mount=type=cache,target=/root/.cache <<EOT
    set -euo pipefail
    # golangci-lint works mainly like go run/go test, ie., per go module
    # https://github.com/golangci/golangci-lint/issues/2654#issuecomment-1606439587
    golangci-lint run -v $(go list -f '{{.Dir}}/...' -m | xargs)
EOT

FROM golang AS govulncheck
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=tmpfs,target=/go/src/ \
    go install "golang.org/x/vuln/cmd/govulncheck@latest" \
    && govulncheck -version

FROM golang AS do-govulncheck
ARG TARGETARCH
ARG GO_VERSION
COPY --link --from=govulncheck /go/bin/govulncheck /go/bin/govulncheck
WORKDIR /govulncheck
ENV GOARCH=${TARGETARCH}
ENV GOTOOLCHAIN=go${GO_VERSION}
ENV PATH=/go/bin:$PATH
RUN --mount=type=bind,target=.,ro <<EOT
    set -euo pipefail
    for dir in $(go list -f '{{.Dir}}' -m); do
      (cd "$dir" && govulncheck -show=verbose ./...)
    done
EOT

FROM golang AS gomodguard
ARG GOMODGUARD_VERSION=v1.4.1
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=tmpfs,target=/go/src/ \
    go install "github.com/ryancurrah/gomodguard/cmd/gomodguard@${GOMODGUARD_VERSION}" \
    && gomodguard -help

FROM golang AS do-gomodguard
COPY --link --from=gomodguard /go/bin/gomodguard /go/bin/gomodguard
WORKDIR /modguard
ENV PATH=/go/bin:$PATH
RUN --mount=type=bind,target=.,ro <<EOT
    set -euo pipefail
    for dir in $(go list -f '{{.Dir}}' -m); do
      if [ -f "$dir/.gomodguard.yaml" ]; then
          (cd "$dir" && gomodguard)
      fi
    done
EOT

FROM golang AS addlicense
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=tmpfs,target=/go/src/ \
    go install "github.com/google/addlicense@latest"

FROM golang AS do-license-check
COPY --link --from=addlicense /go/bin/addlicense /go/bin/addlicense
WORKDIR /app
RUN --mount=type=bind,target=.,ro \
    addlicense -check -c "Docker, Inc." -y "2025-2026" -l apache \
    -ignore "vendor/**" -ignore "**/*.pb.go" -ignore "**/resolverv1connect/*.go" .

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
