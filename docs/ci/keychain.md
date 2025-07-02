# Keychain CI

## Understand the Process

```mermaid
flowchart TD
    A[CI] -->|macOS vm| B(Run Test)
    A[CI] -->|windows vm| C(Run Test)
    A[CI] -->|linux vm| D[Buildkit]
    D -->|fedora| E(Run Test)
    D -->|ubuntu| F(Run Test)
```

The GitHub action spins up three jobs, `linux-keychain`,`test-macos` and
`test-windows`. Each job is run in its own runner. For example `test-macos`
runs inside a `macos` runner. The Linux job is run on an Ubuntu runner, but
the actual tests are run through Docker Buildkit.

There are two Make commands, `make keychain-unit-tests` for macOS and Windows
and `make keychain-linux-unit-tests` for Linux.

## Linux VM and BuildKit

For Linux, instead of dealing with different GH Linux distro runners, we use
docker distro images and buildkit. Thus instead of having to manage different
GH Linux distros and customizing them, we only have to maintain a multistage
Dockerfile which is way simpler.

Linux has two popular keychain backends: `gnome-keyring-daemon` and `kdewallet`.
Each test uses `buildkit` to setup a base image layer specified in `store/Dockerfile`.
There are two base image layers `ubuntu-24.04` and `fedora-43`. They install
all the necessary packages which gives us caching.

Each keychain backend has a script to start them up and ensure they are running
before any Go tests run. They are located in `store/scripts/gnome-keyring`
and `store/scripts/kdewallet`.

On a high-level, each script does:

1. Check relevant binaries available
2. Creates the necessary files for the keyring daemon
3. Starts the dbus daemon
4. Sets the `DBUS_SESSION_BUS_ADDRESS` environment variable
5. Starts the keyring
6. Waits for the keyring to be active by polling dbus over `gdbus`
7. Check if the registered `org.freedesktop.secrets` backend matches what we expect.

Below is a diagram showing the variety of tests run through builkit. We set the
test target using the `DOCKER_TARGET` environment variable.

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

### Fedora

We require `dbus-daemon` since it was removed in favor of `dbus-broker` over
`systemd`. We then use `dbus-daemon` to start the `dbus` service and get the
connection address for `gnome-keyring` and `kwalletd6`.

### Ubuntu

We require `libglib2.0-bin` since we require `gdbus` CLI to talk to the `dbus`
APIs.
