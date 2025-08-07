module github.com/docker/secrets-engine/client

go 1.24.3

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine => ../

require (
	connectrpc.com/connect v1.18.1
	github.com/docker/secrets-engine v0.0.7
	google.golang.org/protobuf v1.36.7
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	golang.org/x/mod v0.26.0 // indirect
)
