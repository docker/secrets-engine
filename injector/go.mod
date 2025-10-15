module github.com/docker/secrets-engine/injector

go 1.25

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine/client => ../client

replace github.com/docker/secrets-engine/x => ../x

require (
	github.com/docker/docker v28.5.1+incompatible
	github.com/docker/secrets-engine/client v0.0.11
	github.com/docker/secrets-engine/x v0.0.4-do.not.use
)

require (
	connectrpc.com/connect v1.18.1 // indirect
	github.com/docker/go-connections v0.6.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	golang.org/x/mod v0.26.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	gotest.tools/v3 v3.5.2 // indirect
)
