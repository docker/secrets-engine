module github.com/docker/secrets-engine/plugin

go 1.24.3

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine => ../

require (
	connectrpc.com/connect v1.18.1
	github.com/containerd/nri v0.9.0
	github.com/docker/secrets-engine v0.0.7
	github.com/stretchr/testify v1.10.0
	google.golang.org/protobuf v1.36.7
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
