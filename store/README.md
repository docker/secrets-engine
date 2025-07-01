# Store

The `store` module is a strict interface for storing credentials and secrets.
It is tightly coupled to the secrets engine and requires a valid `secrets.ID`.

Supported stores include:

- Linux keychain (gnome-keyring and kdewallet)
- macOS keychain
- windows credential management API

## Local Testing

You can run all tests using `go test`. For the `keychain` package the tests
use the supported keychain of your host OS. Linux keychain tests can also be run
inside Docker.

### Keychain tests

For local development, it would make the most sense to just run `keychain-unit-tests`
since it's simply invoking `go test` for only the `keychain` package. CGO is
enabled to support macOS.

To tests Linux on other OSs (like macOS and Windows) or isolated from the host,
you can use the `make keychain-linux-unit-tests` command.

For example:

```console
DOCKER_TARGET=ubuntu-24-gnome-keyring make keychain-linux-unit-tests
```

This will use `buildkit` to target only the `ubuntu-24-gnome-keyring` label inside
the `store/Dockerfile`.

Multiple targets exist:

- ubuntu-24-gnome-keyring
- ubuntu-24-kdewallet
- fedora-43-gnome-keyring
- fedora-43-kdewallet

More information can be found at [keychain/design.md](./keychain/design.md).
