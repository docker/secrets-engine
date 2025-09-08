module github.com/docker/secrets-engine/plugin

go 1.25

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine/x => ../x

require (
	connectrpc.com/connect v1.18.1
	github.com/containerd/nri v0.10.0
	github.com/docker/secrets-engine/x v0.0.2-do.not.use
	github.com/stretchr/testify v1.10.0
	google.golang.org/protobuf v1.36.7
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
