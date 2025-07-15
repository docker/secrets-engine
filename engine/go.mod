module github.com/docker/secrets-engine/engine

go 1.24.3

replace github.com/docker/secrets-engine => ../

replace github.com/docker/secrets-engine/client => ../client

replace github.com/docker/secrets-engine/plugin => ../plugin

require (
	connectrpc.com/connect v1.18.1
	github.com/docker/secrets-engine v0.0.0-00010101000000-000000000000
	github.com/docker/secrets-engine/client v0.0.0-00010101000000-000000000000
	github.com/docker/secrets-engine/plugin v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.10.0
	golang.org/x/sys v0.34.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
