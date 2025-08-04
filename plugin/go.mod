module github.com/docker/secrets-engine/plugin

go 1.24.3

replace github.com/docker/secrets-engine => ../

require (
	connectrpc.com/connect v1.18.1
	github.com/containerd/nri v0.9.0
	github.com/docker/secrets-engine v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.10.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
