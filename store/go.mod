module github.com/docker/secrets-engine/store

go 1.24.3

replace github.com/docker/secrets-engine => ../

require (
	github.com/Benehiko/go-keychain/v2 v2.0.0
	github.com/danieljoos/wincred v1.2.2
	github.com/docker/secrets-engine v0.0.0-00010101000000-000000000000
	github.com/godbus/dbus/v5 v5.1.0
	github.com/spf13/cobra v1.9.1
	github.com/stretchr/testify v1.10.0
	golang.org/x/sys v0.34.0
	golang.org/x/text v0.21.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
