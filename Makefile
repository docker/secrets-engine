MODULE := $(shell sh -c "awk '/^module/ { print \$$2 }' go.mod")
GIT_TAG?=dev
CLI_EXPERIMENTS_EXTENSION_IMAGE?=docker/secrets-engine-extension
GO_VERSION := $(shell sh -c "awk '/^go / { print \$$2 }' go.mod")

export BUF_VERSION := v1.54.0

export NRI_PLUGIN_BINARY := nri-secrets-engine

ifeq ($(OS),Windows_NT)
	WINDOWS = $(OS)
	EXTENSION = .exe
	DOCKER_SOCKET = //var/run/docker.sock
else
	WINDOWS =
	EXTENSION =
	DOCKER_SOCKET = /var/run/docker.sock
endif


# golangci-lint must be pinned - linters can become more strict on upgrade
GOLANGCI_LINT_VERSION := v1.64.5
export GO_VERSION GOPRIVATE GOLANGCI_LINT_VERSION GIT_COMMIT GIT_TAG

BUILDER=buildx-multiarch

DOCKER_BUILD_ARGS := --build-arg GO_VERSION \
          			--build-arg GOLANGCI_LINT_VERSION \
          			--build-arg NRI_PLUGIN_BINARY \
          			--build-arg BUF_VERSION \
          			--build-arg GIT_TAG

GO_TEST := go test
ifneq ($(shell sh -c "which gotestsum 2> /dev/null"),)
GO_TEST := gotestsum --format=testname --
endif

INFO_COLOR = \033[0;36m
NO_COLOR   = \033[m
LINT_PLATFORMS = linux,darwin,windows

multiarch-builder: ## Create buildx builder for multi-arch build, if not exists
	docker buildx inspect $(BUILDER) >/dev/null || docker buildx create --name=$(BUILDER) --driver=docker-container --driver-opt=network=host

format: ## Format code
	@docker buildx build $(DOCKER_BUILD_ARGS) -o . --target=format .

lint: multiarch-builder ## Lint code
	@docker buildx build $(DOCKER_BUILD_ARGS) --pull --builder=$(BUILDER) --target=lint --platform=$(LINT_PLATFORMS) .

clean: ## remove built binaries and packages
	@sh -c "rm -rf bin dist"

unit-tests:
	CGO_ENABLED=0 go test -v -tags="gen" ./...

nri-plugin:
	CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w ${GO_LDFLAGS}" -o ./dist/$(NRI_PLUGIN_BINARY)$(EXTENSION) ./cmd/nri-plugin

nri-plugin-cross: multiarch-builder
	docker buildx build $(DOCKER_BUILD_ARGS) --pull --builder=$(BUILDER) --target=package-nri-plugin --platform=linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64,windows/arm64 -o ./dist .

nri-plugin-package: nri-plugin-cross ## Cross compile and package the host client binaries
	tar -C dist/linux_amd64 -czf dist/$(NRI_PLUGIN_BINARY)-linux-amd64.tar.gz $(NRI_PLUGIN_BINARY)
	tar -C dist/linux_arm64 -czf dist/$(NRI_PLUGIN_BINARY)-linux-arm64.tar.gz $(NRI_PLUGIN_BINARY)
	tar -C dist/darwin_amd64 -czf dist/$(NRI_PLUGIN_BINARY)-darwin-amd64.tar.gz $(NRI_PLUGIN_BINARY)
	tar -C dist/darwin_arm64 -czf dist/$(NRI_PLUGIN_BINARY)-darwin-arm64.tar.gz $(NRI_PLUGIN_BINARY)
	tar -C dist/windows_amd64 -czf dist/$(NRI_PLUGIN_BINARY)-windows-amd64.tar.gz $(NRI_PLUGIN_BINARY).exe
	tar -C dist/windows_arm64 -czf dist/$(NRI_PLUGIN_BINARY)-windows-arm64.tar.gz $(NRI_PLUGIN_BINARY).exe

proto-gen:
	buf generate

help: ## Show this help
	@echo Please specify a build target. The choices are:
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "$(INFO_COLOR)%-30s$(NO_COLOR) %s\n", $$1, $$2}'

.PHONY: run bin format lint unit-tests cross x-package clean help generate docker-mcp
