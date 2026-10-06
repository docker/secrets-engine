module github.com/docker/secrets-engine/plugins/pass

go 1.26.8

replace github.com/docker/secrets-engine/client => ./../../client

replace github.com/docker/secrets-engine/store => ./../../store

replace github.com/docker/secrets-engine/x => ./../../x

require (
	charm.land/bubbles/v2 v2.2.1
	charm.land/bubbletea/v2 v2.0.10
	github.com/charmbracelet/x/term v0.2.2
	github.com/docker/secrets-engine/client v0.1.2
	github.com/docker/secrets-engine/plugin v0.3.2
	github.com/docker/secrets-engine/store v0.4.1
	github.com/docker/secrets-engine/x v0.8.3
	github.com/joho/godotenv v1.5.1
	github.com/spf13/cobra v1.10.1
	github.com/stretchr/testify v1.11.1
	golang.org/x/sys v0.46.0
)

require (
	charm.land/lipgloss/v2 v2.0.5 // indirect
	connectrpc.com/connect v1.19.1 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20260703014108-f5a850f9c2b7 // indirect
	github.com/charmbracelet/x/ansi v0.11.7 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.0 // indirect
	github.com/mattn/go-runewidth v0.0.27 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
