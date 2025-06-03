MODULE := $(shell sh -c "awk '/^module/ { print \$$2 }' go.mod")
GIT_TAG?=dev
CLI_EXPERIMENTS_EXTENSION_IMAGE?=docker/secrets-engine-extension
GO_VERSION := $(shell sh -c "awk '/^go / { print \$$2 }' go.mod")


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
	@sh -c "rm $(DOCKER_X_CLI_PLUGIN_DST) $(DOCKER_MCP_CLI_PLUGIN_DST)"

unit-tests:
	CGO_ENABLED=0 go test -v -tags="gen" ./...

help: ## Show this help
	@echo Please specify a build target. The choices are:
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "$(INFO_COLOR)%-30s$(NO_COLOR) %s\n", $$1, $$2}'

.PHONY: run bin format lint unit-tests cross x-package clean help generate docker-mcp
