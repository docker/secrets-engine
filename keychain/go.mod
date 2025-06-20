module github.com/docker/secrets-engine/keychain

go 1.24.3

replace github.com/docker/secrets-engine => ../

require (
	github.com/docker/secrets-engine v0.0.0-00010101000000-000000000000
	github.com/godbus/dbus/v5 v5.1.0
	github.com/keybase/dbus v0.0.0-20220506165403-5aa21ea2c23a
	github.com/keybase/go-keychain v0.0.1
	github.com/spf13/cobra v1.9.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	golang.org/x/crypto v0.32.0 // indirect
)
