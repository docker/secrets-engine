# Keyring

The keyring package supports macOS, Linux and Windows applications
store, delete and retrieve secrets in a secure way.

The goals are:

- Implement the `store.Store` interface to be tightly coupled with the secrets engine
- Support multiple platforms namely: Linux, macOS, Windows
- Should be a standalone library
- Support credentials of any data structure

The `keyring` package is the successor of the [docker-credential-helpers](https://github.com/docker/docker-credential-helpers/).

It solves a lot of the drawbacks of its predecessor, such as:

- Generic credentials
- Broader use cases (not just a registry credential store)
- Native Go library
- Bundles with your application binary
- More secure

## Linux

Users running Linux with a Desktop Environment usually have access to the
[`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service-spec/latest/index.html) API
via `gnome-keyring` or `kdewallet`.

Usually the `pam_gnome_keyring.so` and `pam_kwallet5.so` would hook into PAM
and automatically unlock the 'login' keyring once the user does a login to their system.
If the 'login' keyring does not exist, it will be created using the user's login password.
If the 'login' keyring is the first keyring created, it will be set as the default.
For more information regarding `gnome-keyring` and PAM, please refer to the
[GnomeKeyring documentation](https://wiki.gnome.org/Projects/GnomeKeyring/Pam)

In the `keyring_linux.go` file, we attempt to use the `login` keyring or in terms
of dbus terminology the `login collection`. If no such keyring can be found,
it defaults finding the default keyring.

To communicate with the `org.freedesktop.secrets` API, we are using `dbus`.
It is a convenient way of communicating without needing any direct C library integration.

At this point in time we have decided to integrate with [keybase/go-keychain](https://github.com/keybase/go-keychain)
instead of implementing all of the `dbus` calls ourselves.

The `keybase/go-keychain` library provides:

- Secure cryptographic communication over the `dbus` connection
- Easy to use API

Some of the drawbacks are:

- Relies on a forked archived [keybase/dbus](https://github.com/keybase/dbus) library
- Low contribution activity

In future we might update the [keybase/dbus](https://github.com/keybase/dbus) with
a more up to date and maintained version, such as [godbus/dbus](https://github.com/godbus/dbus).
