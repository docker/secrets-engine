module github.com/docker/secrets-engine/store

go 1.26.10

// This `replace` is only for CI to function.
// The correct version will get resolved from below when this module is
// retrieved using `go get`.
replace github.com/docker/secrets-engine/x => ../x

require (
	filippo.io/age v1.3.1
	github.com/danieljoos/wincred v1.2.3
	github.com/docker/secrets-engine/x v0.8.5
	github.com/godbus/dbus/v5 v5.1.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.52.0
	golang.org/x/sys v0.46.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	filippo.io/hpke v0.4.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
