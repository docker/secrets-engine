# pass

`docker pass` stores secrets in the local OS keychain and hands them to the
Secrets Engine, which resolves `se://` references in `docker run`,
`docker compose`, and `docker pass run`.

It ships with [Docker Desktop](https://docs.docker.com/desktop/) and with the
Docker CE `docker-secrets-engine-plugins` package. See the
[CLI reference](https://docs.docker.com/reference/cli/docker/pass/) for every
flag.

Secrets live in the host keychain through the
[`store/keychain`](../../store/keychain) package:

- macOS: Keychain
- Linux: Secret Service (GNOME Keyring or KWallet over D-Bus)
- Windows: Credential Manager

## Usage

### Store a secret

```console
$ docker pass set POSTGRES_PASSWORD
Enter secret for POSTGRES_PASSWORD: ******************
```

The value can also come from a pipe or a file, which suits scripts and
multi-line values:

```console
$ printf '%s' my-secret-password | docker pass set POSTGRES_PASSWORD
$ docker pass set my-cert < cert.pem
```

`docker pass set NAME=VALUE` sets the value inline, but it ends up in your
shell history.

Attach non-sensitive metadata with `--metadata key=value`, and overwrite an
existing secret with `--force`.

### List secrets

```console
$ docker pass ls
POSTGRES_PASSWORD
my-cert
```

### Read a secret

```console
$ docker pass get POSTGRES_PASSWORD
ID: POSTGRES_PASSWORD
Value: **********
```

`--reveal` prints the value in plaintext. The Secrets Engine must authorize
the access first and may prompt you.

### Remove secrets

```console
$ docker pass rm GH_TOKEN NPM_TOKEN
$ docker pass rm --all
```

### Use secrets

Reference a secret with `se://NAME` instead of passing its value:

```console
$ docker run --rm -e DB_PASSWORD=se://POSTGRES_PASSWORD busybox sh -c 'echo "$DB_PASSWORD"'
$ docker pass run -e DB_PASSWORD=se://POSTGRES_PASSWORD -- ./deploy.sh
```

`docker pass run` resolves every `se://` reference in the environment, in
`--env-file` files, and in `--env` flags, then starts the command with the
resolved values. It needs the Secrets Engine daemon to be running.

### Troubleshooting

- **Locked keychain (Linux):** log in to the desktop session, or run
  `gnome-keyring-daemon --unlock` on a headless host, then retry.
- **No keychain backend (Linux):** install D-Bus and either GNOME Keyring or
  KWallet.
- **Duplicate item (macOS):** pass `--force` to overwrite the existing secret.

## Embedding the commands

The [`commands`](./commands) package exports the CLI as
[cobra](https://github.com/spf13/cobra) commands. They read the store from the
command's context, so open the keychain with `PassStore` and attach it with
`WithStore`:

```go
package main

import (
	"context"
	"log"

	"github.com/spf13/cobra"

	"github.com/docker/secrets-engine/plugins/pass/commands"
	pass "github.com/docker/secrets-engine/plugins/pass/store"
)

func main() {
	ctx := context.Background()

	kc, err := pass.PassStore(ctx, "com.example.myapp")
	if err != nil {
		log.Fatal(err)
	}

	set, err := commands.SetCommand()
	if err != nil {
		log.Fatal(err)
	}
	get, err := commands.GetCommand()
	if err != nil {
		log.Fatal(err)
	}
	rm, err := commands.RmCommand()
	if err != nil {
		log.Fatal(err)
	}
	run, err := commands.RunCommand()
	if err != nil {
		log.Fatal(err)
	}

	root := &cobra.Command{Use: "pass"}
	root.AddCommand(commands.ListCommand(), set, get, rm, run)

	if err := root.ExecuteContext(commands.WithStore(ctx, kc)); err != nil {
		log.Fatal(err)
	}
}
```

The service group passed to `PassStore` namespaces the keychain entries, so
use one that identifies your application. `PassStore` returns
`keychain.ErrKeychainUnavailable` when the host has no usable keychain; fall
back to another store there if your application supports one.

`set --force`, `get --reveal`, `rm`, and `run` call the Secrets Engine. They
connect to Docker Desktop's socket by default; pass `commands.WithSocketPath`
to use another one, and `commands.WithTimeout` or
`commands.WithResponseTimeout` to change the timeouts.
