module github.com/docker/secrets-engine/client

go 1.24.6

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine/x => ../x

require (
	connectrpc.com/connect v1.18.1
	github.com/docker/secrets-engine/x v0.0.3-do.not.use
	google.golang.org/protobuf v1.36.7
)

require (
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/text v0.28.0 // indirect
)
