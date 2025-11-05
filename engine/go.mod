module github.com/docker/secrets-engine/engine

go 1.25.0

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine/client => ../client

replace github.com/docker/secrets-engine/plugin => ../plugin

replace github.com/docker/secrets-engine/store => ../store

replace github.com/docker/secrets-engine/x => ../x

require (
	connectrpc.com/connect v1.18.1
	github.com/cenkalti/backoff/v5 v5.0.3
	github.com/docker/docker-auth/auth v0.0.1-beta
	github.com/docker/secrets-engine/client v0.0.14
	github.com/docker/secrets-engine/plugin v0.0.17
	github.com/docker/secrets-engine/store v0.0.14
	github.com/docker/secrets-engine/x v0.0.8-do.not.use
	github.com/go-chi/chi/v5 v5.2.3
	github.com/hashicorp/yamux v0.1.2
	github.com/stretchr/testify v1.11.1
	go.opentelemetry.io/otel v1.38.0
	go.opentelemetry.io/otel/sdk v1.38.0
	go.opentelemetry.io/otel/trace v1.38.0
	golang.org/x/sys v0.35.0
	google.golang.org/protobuf v1.36.8
)

require (
	github.com/danieljoos/wincred v1.2.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.38.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.38.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.38.0 // indirect
	go.opentelemetry.io/proto/otlp v1.7.1 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250825161204-c5933d9347a5 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250825161204-c5933d9347a5 // indirect
	google.golang.org/grpc v1.75.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
