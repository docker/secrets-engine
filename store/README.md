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

More information can be found at [./docs/test.md](./docs/test.md).
