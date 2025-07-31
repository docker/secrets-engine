module github.com/docker/secrets-engine/client

go 1.24.3

replace github.com/docker/secrets-engine => ../

require (
	connectrpc.com/connect v1.18.1
	github.com/docker/secrets-engine v0.0.0-00010101000000-000000000000
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	golang.org/x/mod v0.26.0 // indirect
)
