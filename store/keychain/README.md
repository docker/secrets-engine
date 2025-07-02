# Store Keychain

Keychain integrates with the OS keystore. It supports Linux, macOS and Windows
and can be used directly with `keychain.New`.

- Linux uses the [`org.freedesktop.secrets` API](https://specifications.freedesktop.org/secret-service-spec/latest/index.html).
- macOS uses the [macOS Keychain services API](https://developer.apple.com/documentation/security/keychain-services).
- Windows uses the [Windows Credential Manager API](https://learn.microsoft.com/en-us/windows/win32/api/wincred/)

For more design implementation see [../docs/keychain/design.md](../docs/keychain/design.md).

## Quickstart

```go
import "github.com/docker/secrets-engine/store/keychain"

func main() {
    kc, err := keychain.New(
        "service-group",
        "service-name",
		func() *mocks.MockCredential {
			return &mocks.MockCredential{}
		},
    )
}
```

### Secrets

The `keychain` assumes that any secret stored would conform to the `store.Secret`
interface. This allows the `keychain` to store secrets of any type and leaves
it up to the implementer to decide how they would like their secret parsed.
