# Store posixage

The posixage store is a POSIX compliant encrypted file store. It uses [age](https://github.com/filoSottile/age)
to encrypt/decrypt its files and has support for password, ssh and age keys.

## Quickstart

```go
import "github.com/docker/secrets-engine/store/posixage"

func main() {
    root, err := os.OpenRoot("my/secrets/path")
    if err != nil {
        panic(err)
    }

    s, err := posixage.New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
		)
}
```

The store allows you to register multiple encryption and decryption callback
functions. Each callback gives your application control over how to retrieve
the required data — for example, from environment variables, a configuration
file, or via an interactive user prompt.

### Features

- Support for multiple encryption functions
- Support for multiple decryption functions

Callbacks are invoked in the order they are registered. For decryption, the
store tries each callback in sequence, and the first one that successfully
provides a valid key will return the decrypted secret.

Here's an example of accepting multiple passwords for encryption:

```go
import "github.com/docker/secrets-engine/store/posixage"

func main() {
    root, err := os.OpenRoot("my/secrets/path")
    if err != nil {
        panic(err)
    }

    s, err := posixage.New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
            WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(bobPassword), nil
			}),
            WithEncryptionCallbackFunc[EncryptionAgeX25519](func(_ context.Context) ([]byte, error) {
				return []byte(identity.Recipient().String()), nil
			}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
		)
}
```

### Secrets

Any secret format is supported as long as it conforms to the `store.Secret` interface.
