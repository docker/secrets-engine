# Keyring

The `keyring` package is a convenient cross-platform library that supports
storing any data inside the OS keychain.

## How does this compare to the [docker-credential-helpers](https://github.com/docker/docker-credential-helpers/)?

It achieves a similar goal, but the main distinction is in its purpose.
The `docker-credential-helpers` were created with the explicit intent of storing
remote service credentials, such as Image Registry credentials. Each value is
linked to a hostname instead of a generic key.

The `keyring` package is tightly coupled to the secrets engine `secrets.ID` which
allows for more generic identifiers but in a strict format. A key can be specified
as `key=realm/group/application/username`.

The drawbacks of the credential helper is that it is shipped as a separate binary.
In the past this was necessary, so that external applications could access Docker
specific credentials. It has, however, caused a lot of unexpected headache.

Many users face the problem that the credential helper binary goes missing from
the system PATH or the docker config file gets altered, breaking Docker Desktop
or the Docker CLI from properly fetching login credentials.

With the Secrets Engine the need for shipping a separate binary becomes unnecessary
and moving the credential helper into a library would reduce the burden users
are experiencing.

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

### Eager availability check

`New` eagerly verifies that the keychain backend is reachable before returning,
so callers can detect an unusable host (for example WSL or a headless machine
with no D-Bus session bus, or a desktop with no `gnome-keyring`/`kwallet`
running) at construction time and fall back gracefully:

```go
st, err := keychain.New(group, name, factory)
if errors.Is(err, keychain.ErrKeychainUnavailable) {
    // backend unreachable on this host — fall back to another store
}
```

On Linux the check dials a fresh connection through the same path every
operation uses and asks the **D-Bus daemon** whether `org.freedesktop.secrets`
has an owner, via `org.freedesktop.DBus.NameHasOwner` with `FlagNoAutoStart`. It
is intentionally **prompt-safe and side-effect-free**: the query is answered by
`dbus-daemon` from its own name registry and is never forwarded to the Secret
Service backend, so it can never reach a password/unlock prompt, never activates
the backend, and never touches a collection or item. The probe connection is
closed immediately, preserving the fresh-connection-per-operation design.

`ErrKeychainUnavailable` is the caller's fallback signal and is **distinct from**
`ErrNoDefaultCollection`: the availability check does not assert that a
collection exists, so a reachable-but-uninitialized keyring still passes `New`
and surfaces `ErrNoDefaultCollection` lazily on the first operation, as before.
On macOS and Windows the check is a no-op (`New` never returns
`ErrKeychainUnavailable` there).
