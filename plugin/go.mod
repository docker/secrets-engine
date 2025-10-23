module github.com/docker/secrets-engine/plugin

go 1.25

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine/x => ../x

require (
	connectrpc.com/connect v1.18.1
	github.com/containerd/nri v0.10.0
	github.com/docker/secrets-engine/x v0.0.4-do.not.use
	github.com/stretchr/testify v1.11.1
	google.golang.org/protobuf v1.36.8
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/sdk v1.38.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
