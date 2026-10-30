module github.com/docker/secrets-engine/x

go 1.26.10

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine/secrets => ../secrets

require (
	connectrpc.com/connect v1.19.1
	github.com/docker/secrets-engine/secrets v1.0.0
	github.com/hashicorp/yamux v0.1.2
	github.com/stretchr/testify v1.11.1
	golang.org/x/mod v0.41.0
	golang.org/x/sys v0.46.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
