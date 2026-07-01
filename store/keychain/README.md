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

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/keychain"
	"github.com/docker/secrets-engine/store/mocks"
)

func main() {
	ctx := context.Background()
	kc, err := keychain.New(
		ctx,
		"service-group",
		"service-name",
		func(_ context.Context, _ store.ID) *mocks.MockCredential {
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

### Secrets

The `keychain` assumes that any secret stored would conform to the `store.Secret`
interface. This allows the `keychain` to store secrets of any type and leaves
it up to the implementer to decide how they would like their secret parsed.

## Example CLI

The `keychain` package also contains an example CLI tool to test out how a real
application might interact with the host keychain.

You can build the CLI by running `go build` inside the `store/` root directory.

```console
$ go build -o keychain-cli ./keychain/cmd/
$ ./keychain-cli
```
