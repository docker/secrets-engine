GIT_TAG?=dev
GO_VERSION := $(shell sh -c "awk '/^go / { print \$$2 }' go.work")

# For latest version, see: https://github.com/bufbuild/buf/tags
export BUF_VERSION := v1.56.0

export NRI_PLUGIN_BINARY := nri-secrets-engine
export MYSECRET_BINARY := docker-mysecret
export ENGINE_BINARY := secrets-engine

ifeq ($(OS),Windows_NT)
	WINDOWS = $(OS)
	EXTENSION = .exe
	DOCKER_SOCKET = //var/run/docker.sock
	DOCKER_MYSECRET_DST = $(USERPROFILE)\.docker\cli-plugins\$(MYSECRET_BINARY)$(EXTENSION)
else
	WINDOWS =
	EXTENSION =
	DOCKER_SOCKET = /var/run/docker.sock
	DOCKER_MYSECRET_DST = $(HOME)/.docker/cli-plugins/$(MYSECRET_BINARY)$(EXTENSION)
endif


# golangci-lint must be pinned - linters can become more strict on upgrade
GOLANGCI_LINT_VERSION := v2.4.0
export GO_VERSION GOPRIVATE GOLANGCI_LINT_VERSION GIT_COMMIT GIT_TAG

BUILDER=buildx-multiarch

DOCKER_BUILD_ARGS := --build-arg GO_VERSION \
          			--build-arg GOLANGCI_LINT_VERSION \
          			--build-arg NRI_PLUGIN_BINARY \
          			--build-arg MYSECRET_BINARY \
          			--build-arg ENGINE_BINARY \
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
	flags="--ssh default"; \
	if [ -n "$$GH_TOKEN" ]; then \
		flags="--secret id=GH_TOKEN,env=GH_TOKEN"; \
	fi; \
	echo "Using build flags: $$flags"; \
	docker buildx build $(DOCKER_BUILD_ARGS) $$flags --pull --builder=$(BUILDER) --target=lint --platform=$(LINT_PLATFORMS) .

clean: ## remove built binaries and packages
	@sh -c "rm -rf bin dist"

unit-tests:
	pids=""; \
	err=0; \
	go test -trimpath -v $(shell go list ./client/...) & pids="$$pids $$!"; \
	go test -trimpath -v $(shell go list ./engine/...) & pids="$$pids $$!"; \
	go test -trimpath -v $(shell go list ./mysecret/...) & pids="$$pids $$!"; \
	go test -trimpath -v $(shell go list ./plugin/...) & pids="$$pids $$!"; \
	go test -trimpath -v $(shell go list ./x/...)      & pids="$$pids $$!"; \
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
	CGO_ENABLED=1 go test -trimpath -v $$(go list ./store/keychain/...)

engine-unit-tests:
	go test -trimpath -v $$(go list ./engine/...)

mysecret:
	CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o ./dist/$(MYSECRET_BINARY)$(EXTENSION) ./mysecret
	rm "$(DOCKER_MYSECRET_DST)" || true
	cp "dist/$(MYSECRET_BINARY)$(EXTENSION)" "$(DOCKER_MYSECRET_DST)"

mysecret-cross: multiarch-builder
	docker buildx build $(DOCKER_BUILD_ARGS) --pull --builder=$(BUILDER) --target=package-mysecret --file mysecret/Dockerfile --platform=linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64,windows/arm64 -o ./dist .

engine:
	CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o ./dist/$(ENGINE_BINARY)$(EXTENSION) ./engine/daemon

engine-cross: multiarch-builder
	docker buildx build $(DOCKER_BUILD_ARGS) --pull --builder=$(BUILDER) --target=package-engine \
		--file engine/daemon/Dockerfile \
		--platform=linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64,windows/arm64 \
		-o ./dist .

nri-plugin:
	CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w" -o ./dist/$(NRI_PLUGIN_BINARY)$(EXTENSION) ./cmd/nri-plugin

nri-plugin-cross: multiarch-builder
	docker buildx build $(DOCKER_BUILD_ARGS) --pull --builder=$(BUILDER) --target=package-nri-plugin --platform=linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64,windows/arm64 -o ./dist .

nri-plugin-package: nri-plugin-cross ## Cross compile and package the host client binaries
	tar -C dist/linux_amd64 -czf dist/$(NRI_PLUGIN_BINARY)-linux-amd64.tar.gz $(NRI_PLUGIN_BINARY)
	tar -C dist/linux_arm64 -czf dist/$(NRI_PLUGIN_BINARY)-linux-arm64.tar.gz $(NRI_PLUGIN_BINARY)
	tar -C dist/darwin_amd64 -czf dist/$(NRI_PLUGIN_BINARY)-darwin-amd64.tar.gz $(NRI_PLUGIN_BINARY)
	tar -C dist/darwin_arm64 -czf dist/$(NRI_PLUGIN_BINARY)-darwin-arm64.tar.gz $(NRI_PLUGIN_BINARY)
	tar -C dist/windows_amd64 -czf dist/$(NRI_PLUGIN_BINARY)-windows-amd64.tar.gz $(NRI_PLUGIN_BINARY).exe
	tar -C dist/windows_arm64 -czf dist/$(NRI_PLUGIN_BINARY)-windows-arm64.tar.gz $(NRI_PLUGIN_BINARY).exe

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

.PHONY: run bin format lint proto-lint proto-generate unit-tests clean help keychain-linux-unit-tests keychain-unit-tests mysecret mysecret-cross engine engine-cross
