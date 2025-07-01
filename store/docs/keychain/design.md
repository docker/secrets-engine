# Keyring

The `keyring` package is the successor of the [docker-credential-helpers](https://github.com/docker/docker-credential-helpers/)
and supports macOS, Linux and Windows applications.

It solves a lot of the drawbacks of its predecessor, such as:

- Support for Generic credentials
- Native Go library that bundles with your application binary
- Broader use cases: It can be used to store credentials or any secret.
  It is designed so that the implemeter has more choice. The credential helper
  was designed to only support credentials from remote services (e.g. Image Registry)
- More secure: since it is a library, the implementer can decide how much
  data from the store they should expose outside of the application. With the
  credential helper it is a standalone binary with the purpose of printing
  credentials to `stdOut`, any application can by default access whatever the
  credential helper has stored.

## Linux

Users running Linux with a desktop environment usually have access to the
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
