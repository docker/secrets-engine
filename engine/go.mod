module github.com/docker/secrets-engine/engine

go 1.25.0

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine/client => ../client

replace github.com/docker/secrets-engine/mysecret => ../mysecret

replace github.com/docker/secrets-engine/plugin => ../plugin

replace github.com/docker/secrets-engine/store => ../store

replace github.com/docker/secrets-engine/x => ../x

require (
	connectrpc.com/connect v1.18.1
	github.com/cenkalti/backoff/v5 v5.0.3
	github.com/docker/docker-auth/auth v0.0.1-beta
	github.com/docker/secrets-engine/client v0.0.7
	github.com/docker/secrets-engine/mysecret v0.0.0-00010101000000-000000000000
	github.com/docker/secrets-engine/plugin v0.0.7
	github.com/docker/secrets-engine/store v0.0.7
	github.com/docker/secrets-engine/x v0.0.1-do.not.use
	github.com/hashicorp/yamux v0.1.2
	github.com/stretchr/testify v1.10.0
	golang.org/x/sys v0.35.0
	google.golang.org/protobuf v1.36.7
)

require (
	github.com/Benehiko/go-keychain/v2 v2.0.0 // indirect
	github.com/danieljoos/wincred v1.2.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
