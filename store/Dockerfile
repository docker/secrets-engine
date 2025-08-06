ARG GO_VERSION=latest

FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION}-alpine AS go-base

FROM --platform=${BUILDPLATFORM} fedora:43 AS fedora43
RUN dnf install -y gnome-keyring kf6-kwallet dbus-daemon bash
COPY --from=go-base /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
RUN useradd -ms /bin/bash user
USER user
WORKDIR /app
RUN --mount=type=bind,target=.

FROM --platform=${BUILDPLATFORM} ubuntu:24.04 AS ubuntu24
RUN apt update && apt install -y --no-install-recommends libglib2.0-bin dbus gnome-keyring kwalletmanager libqca-qt5-2-plugins bash
COPY --from=go-base /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
RUN useradd -ms /bin/bash user
USER user
WORKDIR /app
RUN --mount=type=bind,target=.

FROM fedora43 AS fedora-43-gnome-keyring
ENV CGO_ENABLED=0
USER user
WORKDIR /app
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    bash -c "set -euxo pipefail; /app/store/scripts/gnome-keyring"

FROM fedora43 AS fedora-43-kdewallet
ENV CGO_ENABLED=0
USER user
WORKDIR /app
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    bash -c "set -euxo pipefail; /app/store/scripts/kdewallet"

FROM ubuntu24 AS ubuntu-24-gnome-keyring
ENV CGO_ENABLED=0
USER user
WORKDIR /app
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    bash -c "set -euxo pipefail; /app/store/scripts/gnome-keyring"

FROM ubuntu24 AS ubuntu-24-kdewallet
ENV CGO_ENABLED=0
USER user
WORKDIR /app
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    bash -c "set -euxo pipefail; /app/store/scripts/kdewallet"
