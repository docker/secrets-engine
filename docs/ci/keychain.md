# Keychain CI

The keychain tests are split between macOS, Linux and Windows. There are two
make commands: `make keychain-unit-tests` and `make keychain-linux-unit-tests`.

For local development, it would make the most sense to just run `keychain-unit-tests`
since it's simply invoking `go test` for only the `keychain` package. CGO is
enabled to support macOS.

Since there are so many different scenarios in Linux, the GH runners would
be a headache to setup and maintain and we don't have access to a variety of
distros.

Linux has two popular keychain backends: `gnome-keyring-daemon` and `kdewallet`.
To cover a variety of environments, we setup `Ubuntu 24.04` and `Fedora 43` with
both backends in different test runs.

To test this locally you can run `DOCKER_TARGET=ubuntu-24-gnome-keyring make keychain-linux-unit-tests`.
This will use `buildkit` to target only the `ubuntu-24-gnome-keyring` label inside
the `store/Dockerfile`.

Each backend has a script to start them up and ensure they are running before
any Go tests even run. They are located in `store/scripts/gnome-keyring` and
`store/scripts/kdewallet`.

### Fedora

On Fedora we install `gnome-keyring`, `kf6-kwallet` and `dbus-daemon`.
We require `dbus-daemon` since it was removed in favor of `dbus-broker` over
`systemd`. We then use `dbus-daemon` to start the `dbus` service and get the
connection address for `gnome-keyring` and `kwalletd6`.

Fedora 43 is the latest at the time of writing and has the latest packages and
changes to `kdewallet` and `dbus`.

### Ubuntu

On Ubuntu we install `libglib2.0-bin`, `dbus`, `gnome-keyring`, `kwalletmanager`.
We require `libglib2.0-bin` since we require `gdbus` CLI to talk to the `dbus`
APIs.

## Understand the Process

The GitHub action spins up three jobs, `linux-keychain`,`test-macos` and `test-windows`.
For `linux-keychain` we then have four tests:

- `ubuntu-24-gnome-keyring`
- `ubuntu-24-kdewallet`
- `fedora-43-gnome-keyring`
- `fedora-43-kdewallet`

Each test uses `buildkit` to setup a base image layer specified in `store/Dockerfile`.
There are two base image layers `ubuntu-24.04` and `fedora-43`. They install
all the necessary packages which gives us caching.

Then for each of the four tests listed above we invoke the relevant scripts stored
in `store/scripts`.

On a high-level, each script does:

1. Check relavant binaries avaliable
2. Creates the necessary files for the keyring daemon
3. Starts the dbus daemon
4. Sets the `DBUS_SESSION_BUS_ADDRESS` environment variable
5. Starts the keyring
6. Waits for the keyring to be active by polling dbus over `gdbus`
7. Check if the registered `org.freedesktop.secrets` backend matches what we expect.
