# Store Keychain

Keychain integrates with the OS keystore. It supports Linux, macOS and Windows
and can be used directly with `keychain.New`.

- Linux uses the [`org.freedesktop.secrets` API](https://specifications.freedesktop.org/secret-service-spec/latest/index.html).
- macOS uses the [macOS Keychain services API](https://developer.apple.com/documentation/security/keychain-services).
- Windows uses the [Windows Credential Manager API](https://learn.microsoft.com/en-us/windows/win32/api/wincred/)

For more design implementation see [../docs/keychain/design.md](../docs/keychain/design.md).

## Quickstart

```go
import (
	"context"

	"github.com/docker/secrets-engine/secrets"
	"github.com/docker/secrets-engine/store/keychain"
	"github.com/docker/secrets-engine/store/mocks"
)

func main() {
	ctx := context.Background()
	kc, err := keychain.New(
		ctx,
		"service-group",
		"service-name",
		func(_ context.Context, _ secrets.ID) *mocks.MockCredential {
			return &mocks.MockCredential{}
		},
	)
	if err != nil {
		// handle error (see Availability below for detecting an unusable host)
	}
	_ = kc
}
```

### Availability

`keychain.New` eagerly verifies that the OS keychain backend is reachable before
returning. On a host without a usable keychain — for example WSL or a headless
machine with no D-Bus session bus, or a Linux desktop with no
`gnome-keyring`/`kwallet` running — it returns an error that matches
`keychain.ErrKeychainUnavailable`, so callers can detect this at construction
time and fall back to another store instead of failing on the first operation:

```go
st, err := keychain.New(ctx, group, name, factory)
if errors.Is(err, keychain.ErrKeychainUnavailable) {
    // keychain unreachable on this host — use a fallback store
}
```

The `ctx` bounds the availability probe. On Linux it bounds the probe's D-Bus
connection handshake and its single `NameHasOwner` round-trip and lets you cancel
construction; if you pass a context without a deadline, `New` applies a short
internal default so it stays responsive on an unreachable host, and any deadline
you set yourself always wins. The probe never launches a session bus
(`dbus-launch`) and, as a fast path, checks that the session bus socket exists
before dialing. The check is prompt-safe and side-effect-free: it asks the D-Bus
daemon whether the Secret Service is registered and never touches your stored
secrets. On macOS and Windows the check is a no-op (and `ctx` is unused). See
[../docs/keychain/design.md](../docs/keychain/design.md) for details.

### Locked collections (Linux)

A reachable keychain can still hold a locked collection. This is the default
state on headless Linux hosts with SSH key-only logins: PAM has no password to
auto-unlock the login keyring, so it is locked after every keyring-daemon
restart.

A store operation that finds the collection locked asks the Secret Service to
unlock it. On a passwordless keyring this succeeds silently. On a
password-protected keyring it opens the backend's unlock prompt. If the prompt
is dismissed (gnome-keyring does this immediately when no prompter can be
shown), times out, or the operation's context expires, the operation fails
with an error matching `keychain.ErrCollectionLocked`:

```go
_, err := st.Get(ctx, id)
if errors.Is(err, keychain.ErrCollectionLocked) {
    // The collection still holds the user's credentials. Tell the user how
    // to unlock it, for example by logging in to the desktop session or
    // running gnome-keyring-daemon --unlock. Do not fall back to another
    // store; that would split credentials across stores.
}
```

The operation's `ctx` bounds the prompt wait, so a caller can set its own
deadline; an internal 30 second cap always applies. Unavailable means there is
no keychain to use, so fall back. Locked means the keychain and credentials
exist but need the user's help, so surface the remediation and do not fall
back.

### Secrets

The `keychain` assumes that any secret stored would conform to the `secrets.Secret`
interface. This allows the `keychain` to store secrets of any type and leaves
it up to the implementer to decide how they would like their secret parsed.

## Example

For a real application built on the `keychain` store, see the
[`docker pass` commands](https://github.com/docker/secrets-engine/tree/main/plugins/pass/commands).
The [pass plugin README](https://github.com/docker/secrets-engine/tree/main/plugins/pass)
explains how to use the CLI and how it wires the commands to the keychain.
