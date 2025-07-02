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

## Example CLI

The `keychain` package also contains an example CLI tool to test out how a real
application might interact with the host keychain.

You can build the CLI by running `go build` inside the `store/` root directory.

```console
⋊> ~/G/s/store on keychain ⨯ go build -o keychain-cli ./keychain/cmd/
⋊> ~/G/s/store on keychain ⨯ ./keychain-cli                                                                                                                       13:24:48
Usage:
   [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  delete
  get
  help        Help about any command
  list
  store

Flags:
  -h, --help   help for this command

Use " [command] --help" for more information about a command.
```
