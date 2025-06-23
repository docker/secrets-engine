# Store Keychain

Keychain integrates with the OS keystore. It supports Linux, macOS and Windows
and can be used directly with `keychain.New`.

- Linux uses the [`org.freedesktop.secrets` API](https://www.freedesktop.org/wiki/Specifications/secret-storage-spec/secrets-api-0.1.html).
- macOS uses the [macOS Keychain services API](https://developer.apple.com/documentation/security/keychain-services).

## Quickstart

```go
import "github.com/docker/secrets-engine/store/keychain"

func main() {
    kc, err := keychain.New[*]()
}
```
