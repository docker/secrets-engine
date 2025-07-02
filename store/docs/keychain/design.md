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
