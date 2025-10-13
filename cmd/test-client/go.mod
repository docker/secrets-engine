module github.com/docker/secrets-engine/test-client

go 1.25.0

replace github.com/docker/secrets-engine/client => ../../client/

replace github.com/docker/secrets-engine/x => ../../x

require (
	github.com/docker/secrets-engine/client v0.0.9
	github.com/docker/secrets-engine/x v0.0.5-do.not.use
)

require (
	connectrpc.com/connect v1.18.1 // indirect
	golang.org/x/mod v0.26.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
)
