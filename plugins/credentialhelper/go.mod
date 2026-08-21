module github.com/docker/secrets-engine/plugins/credentialhelper

go 1.25.13

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine/plugin => ../../plugin

require (
	github.com/docker/docker-credential-helpers v0.9.4
	github.com/docker/secrets-engine/plugin v0.3.1
	github.com/docker/secrets-engine/x v0.7.0-do.not.use
	github.com/stretchr/testify v1.11.1
)

require (
	connectrpc.com/connect v1.19.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
