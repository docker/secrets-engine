GIT_TAG?=dev
GO_VERSION := $(shell sh -c "awk '/^go / { print \$$2 }' go.work")

# For latest version, see: https://github.com/bufbuild/buf/tags
export BUF_VERSION := v1.56.0

ifeq ($(OS),Windows_NT)
	WINDOWS = $(OS)
	EXTENSION = .exe
	DOCKER_SOCKET = //var/run/docker.sock
	DOCKER_PASS_DST = $(USERPROFILE)\.docker\cli-plugins\$(PASS_BINARY)$(EXTENSION)
else
	WINDOWS =
	EXTENSION =
	DOCKER_SOCKET = /var/run/docker.sock
	DOCKER_PASS_DST = $(HOME)/.docker/cli-plugins/$(PASS_BINARY)$(EXTENSION)
endif

# golangci-lint must be pinned - linters can become more strict on upgrade
GOLANGCI_LINT_VERSION := v2.4.0
export GO_VERSION GOPRIVATE GOLANGCI_LINT_VERSION GIT_COMMIT GIT_TAG

BUILDER=buildx-multiarch

DOCKER_BUILD_ARGS := --build-arg GO_VERSION \
          			--build-arg GOLANGCI_LINT_VERSION \
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
	@set -e; \
	docker buildx build $(DOCKER_BUILD_ARGS) --pull --builder=$(BUILDER) --target=lint --platform=$(LINT_PLATFORMS) .

clean: ## remove built binaries and packages
	@sh -c "rm -rf bin dist"

.PHONY: unit-tests
unit-tests:
	pids=""; \
	err=0; \
	for dir in $(shell go list -f '{{.Dir}}' -m); do \
		case "$$dir" in \
			*/store) continue ;; \
		esac; \
	  	go test -trimpath -race -v $$(go list "$$dir/...")  & pids="$$pids $$!"; \
	done; \
	for p in $$pids; do \
		wait $$p || err=$$?; \
	done; \
	if [ $$err -ne 0 ]; then \
		echo "ERROR: $$err"; \
		exit $$err; \
	fi

keychain-linux-ci-unit-tests:
	@docker buildx build $(DOCKER_BUILD_ARGS) --target=$(DOCKER_TARGET) --file store/Dockerfile .

keychain-linux-unit-tests:
	docker buildx bake --set '*.args.GO_VERSION=${GO_VERSION}' --file store/docker-bake.hcl

keychain-unit-tests:
	CGO_ENABLED=1 go test -trimpath -race -v $$(go list ./store/keychain/...)

runtime-unit-tests:
	go test -trimpath -race -v $$(go list ./runtime/...)

proto-generate:
	@docker buildx build $(DOCKER_BUILD_ARGS) -o . --target=proto-generate .

proto-lint:
	@docker buildx build $(DOCKER_BUILD_ARGS) --target=proto-lint .

mod: export GOPRIVATE=github.com/docker/*
mod:
	@echo "Tidying all Go modules..."
	@for d in $$(find . -name "go.mod" -exec dirname {} \;); do \
		echo ">>> Processing $$d"; \
		rm -f $$d/go.sum; \
		( cd $$d && go mod tidy ); \
	done
	@echo "Syncing and vendoring workspace..."
	@go work sync
	@go work vendor

.PHONY: govulncheck
govulncheck:
	@docker buildx build $(DOCKER_BUILD_ARGS) --target=do-govulncheck --platform=linux/arm64,linux/amd64 .

.PHONY: gomodguard
gomodguard:
	@docker buildx build $(DOCKER_BUILD_ARGS) --target=do-gomodguard .

define HELP_BUMP
Usage: make bump MOD=<module>

Examples:
  make bump MOD=engine

Alternatively, run the go release helper directly:
  go run ./x/release --help
  go run ./x/release --dry engine

endef
export HELP_BUMP

bump: MOD?=
bump:
	@if [ -z "$(MOD)" ]; then \
		echo "$$HELP_BUMP"; \
		exit 1; \
	fi
	git fetch --tags
	git diff --quiet
	go run ./x/release $(MOD)

help: ## Show this help
	@echo Please specify a build target. The choices are:
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "$(INFO_COLOR)%-30s$(NO_COLOR) %s\n", $$1, $$2}'

.PHONY: run bin format lint proto-lint proto-generate clean help keychain-linux-unit-tests keychain-unit-tests
