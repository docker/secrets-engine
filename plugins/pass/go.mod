module github.com/docker/secrets-engine/plugins/pass

go 1.25.12

replace github.com/docker/secrets-engine/client => ./../../client

replace github.com/docker/secrets-engine/store => ./../../store

replace github.com/docker/secrets-engine/x => ./../../x

require (
	github.com/docker/secrets-engine/client v0.0.30
	github.com/docker/secrets-engine/plugin v0.3.0
	github.com/docker/secrets-engine/store v0.2.1
	github.com/docker/secrets-engine/x v0.3.0-do.not.use
	github.com/joho/godotenv v1.5.1
	github.com/spf13/cobra v1.10.1
	github.com/stretchr/testify v1.11.1
)

require (
	connectrpc.com/connect v1.19.1 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
