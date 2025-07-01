# Test

The store can be tested using the `go test` command. For the `keychain` package
this might require further tweaks depending on the OS you are running on.

## Keychain tests

For local development, it would make the most sense to just run `keychain-unit-tests`
since it's simply invoking `go test` for only the `keychain` package. CGO is
enabled to support macOS.

To test Linux on other OSs (like macOS and Windows) or isolated from the host,
you can use the `make keychain-linux-unit-tests` command. It uses Docker to
spin up the necessary environment required to run the test.

```console
DOCKER_TARGET=ubuntu-24-gnome-keyring make keychain-linux-unit-tests
```

For Linux keychain we have four sub-tests:

```mermaid
flowchart TD
    A[Linux Keychain Test] -->|ubuntu| B(Run gnome-keyring)
    A -->|ubuntu| C(Run kdewallet)
    A -->|fedora| D(Run gnome-keyring)
    A -->|fedora| E(Run kdewallet)
```

- `ubuntu-24-gnome-keyring`
- `ubuntu-24-kdewallet`
- `fedora-43-gnome-keyring`
- `fedora-43-kdewallet`

This will use `buildkit` to target only the `ubuntu-24-gnome-keyring` label inside
the `store/Dockerfile`.
