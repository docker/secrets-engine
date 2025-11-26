module github.com/docker/secrets-engine/cmd/engine

go 1.25.0

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine/engine => ../../engine

replace github.com/docker/secrets-engine/pass => ../../pass

replace github.com/docker/secrets-engine/plugins/credentialhelper => ../../plugins/credentialhelper/

replace github.com/docker/secrets-engine/store => ../../store

replace github.com/docker/secrets-engine/x => ../../x

require (
	github.com/docker/secrets-engine/engine v0.0.26
	github.com/docker/secrets-engine/pass v0.0.14
	github.com/docker/secrets-engine/plugins/credentialhelper v0.0.19
	github.com/docker/secrets-engine/x v0.0.11-do.not.use
)

require (
	connectrpc.com/connect v1.18.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/docker/docker-auth/auth v0.0.1-beta // indirect
	github.com/docker/docker-credential-helpers v0.9.4 // indirect
	github.com/docker/secrets-engine/plugin v0.0.18 // indirect
	github.com/docker/secrets-engine/store v0.0.17 // indirect
	github.com/go-chi/chi/v5 v5.2.3 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.2 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/cobra v1.10.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.38.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.38.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/sdk v1.38.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.opentelemetry.io/proto/otlp v1.7.1 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/term v0.34.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250825161204-c5933d9347a5 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250825161204-c5933d9347a5 // indirect
	google.golang.org/grpc v1.75.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
)
