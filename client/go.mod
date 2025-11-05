module github.com/docker/secrets-engine/client

go 1.25

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine/x => ../x

require (
	connectrpc.com/connect v1.18.1
	github.com/docker/secrets-engine/x v0.0.7-do.not.use
	google.golang.org/protobuf v1.36.8
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	golang.org/x/mod v0.26.0 // indirect
)
