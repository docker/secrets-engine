package posixage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"testing"

	"filippo.io/age"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/mocks"
	"github.com/docker/secrets-engine/store/posixage/internal/secretfile"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

type testLogger struct {
	t *testing.T
}

// Errorf implements logging.Logger.
func (t *testLogger) Errorf(format string, v ...any) {
	t.t.Logf(format, v...)
}

// Printf implements logging.Logger.
func (t *testLogger) Printf(format string, v ...any) {
	t.t.Logf(format, v...)
}

// Warnf implements logging.Logger.
func (t *testLogger) Warnf(format string, v ...any) {
	t.t.Logf(format, v...)
}

var _ logging.Logger = &testLogger{}

func onlyDirs(f fs.FS) ([]fs.DirEntry, error) {
	var dirs []fs.DirEntry
	return dirs, fs.WalkDir(f, ".", func(_ string, d fs.DirEntry, err error) error {
		if d.Name() == "." {
			return nil
		}
		if d.IsDir() {
			dirs = append(dirs, d)
		}
		return err
	})
}

func TestPOSIXAge(t *testing.T) {
	t.Run("can save encrypted secret", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		masterKey := uuid.NewString()
		s, err := New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithLogger(&testLogger{t}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
		)
		require.NoError(t, err)
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
			Attributes: map[string]string{
				"val1": uuid.NewString(),
				"val2": uuid.NewString(),
			},
		}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Save(t.Context(), id, secret))

		fsFiles, err := onlyDirs(root.FS())
		require.NoError(t, err)
		assert.Len(t, fsFiles, 1)

		encodedID := base64.StdEncoding.EncodeToString([]byte(id.String()))
		assert.Equal(t, encodedID, fsFiles[0].Name())

		secretRoot, err := root.OpenRoot(encodedID)
		require.NoError(t, err)

		metadataFile, err := secretRoot.ReadFile(secretfile.MetadataFileName)
		require.NoError(t, err)

		var m map[string]string
		require.NoError(t, json.Unmarshal(metadataFile, &m))

		assert.EqualValues(t, secret.Metadata(), m)

		encryptedFile, err := secretRoot.ReadFile(secretfile.SecretFileName + "pass")
		require.NoError(t, err)

		unencrypted, err := secret.Marshal()
		require.NoError(t, err)
		assert.NotEqual(t, unencrypted, encryptedFile)

		x := s.(*fileStore[*mocks.MockCredential])
		x.registeredDecryptionFunc = []promptCaller{
			DecryptionPassword(func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
		}
		decryptedFile, err := x.decryptSecret(t.Context(), []secretfile.EncryptedSecret{
			{
				KeyType:       secretfile.PasswordKeyType,
				EncryptedData: encryptedFile,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, unencrypted, decryptedFile)
	})

	t.Run("can get encrypted secret", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		masterKey := uuid.NewString()
		s, err := New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithLogger(&testLogger{t}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
		)
		require.NoError(t, err)
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
			Attributes: map[string]string{
				"val1": uuid.NewString(),
				"val2": uuid.NewString(),
			},
		}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Save(t.Context(), id, secret))

		storeSecret, err := s.Get(t.Context(), id)
		require.NoError(t, err)
		assert.EqualValues(t, secret.Metadata(), storeSecret.Metadata())
		assert.IsType(t, &mocks.MockCredential{}, storeSecret)
		assert.EqualValues(t, secret, storeSecret)
	})

	t.Run("can get all secret metadata", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		masterKey := uuid.NewString()
		s, err := New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithLogger(&testLogger{t}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
		)
		require.NoError(t, err)
		secrets := map[store.ID]*mocks.MockCredential{
			store.MustParseID("something/secret1/" + uuid.NewString()): {
				Username: uuid.NewString(),
				Password: uuid.NewString(),
				Attributes: map[string]string{
					"val1": uuid.NewString(),
					"val2": uuid.NewString(),
				},
			},
			store.MustParseID("something/secret2/" + uuid.NewString()): {
				Username: uuid.NewString(),
				Password: uuid.NewString(),
				Attributes: map[string]string{
					"val3": uuid.NewString(),
					"val4": uuid.NewString(),
				},
			},
		}
		for id, secret := range secrets {
			require.NoError(t, s.Save(t.Context(), id, secret))
		}

		fsFiles, err := onlyDirs(root.FS())
		require.NoError(t, err)
		assert.Len(t, fsFiles, 2)

		storeSecrets, err := s.GetAllMetadata(t.Context())
		require.NoError(t, err)
		assert.Len(t, storeSecrets, 2)

		for id, secret := range secrets {
			assert.IsType(t, &mocks.MockCredential{}, storeSecrets[id])
			assert.EqualValues(t, &mocks.MockCredential{Attributes: secret.Attributes}, storeSecrets[id])
			assert.EqualValues(t, secret.Metadata(), storeSecrets[id].Metadata())
		}
	})

	t.Run("can filter secrets", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		masterKey := uuid.NewString()
		s, err := New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithLogger(&testLogger{t}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
		)
		require.NoError(t, err)

		secretOne := store.MustParseID("something/secret1/" + uuid.NewString())
		secretTwo := store.MustParseID("something2/secret2/" + uuid.NewString())

		secrets := map[store.ID]*mocks.MockCredential{
			secretOne: {
				Username: uuid.NewString(),
				Password: uuid.NewString(),
				Attributes: map[string]string{
					"val1": uuid.NewString(),
					"val2": uuid.NewString(),
				},
			},
			secretTwo: {
				Username: uuid.NewString(),
				Password: uuid.NewString(),
				Attributes: map[string]string{
					"val3": uuid.NewString(),
					"val4": uuid.NewString(),
				},
			},
		}
		for id, secret := range secrets {
			require.NoError(t, s.Save(t.Context(), id, secret))
		}
		fsFiles, err := onlyDirs(root.FS())
		require.NoError(t, err)
		assert.Len(t, fsFiles, 2)

		storeSecrets, err := s.Filter(t.Context(), store.MustParsePattern("something/**"))
		require.NoError(t, err)

		assert.Len(t, storeSecrets, 1)
		assert.IsType(t, &mocks.MockCredential{}, storeSecrets[secretOne])
		assert.EqualValues(t, secrets[secretOne], storeSecrets[secretOne])
	})

	t.Run("can use multiple keys to encrypt and decrypt", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		masterKey := uuid.NewString()
		identity, err := age.GenerateX25519Identity()
		require.NoError(t, err)

		s, err := New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithLogger(&testLogger{t}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithEncryptionCallbackFunc[EncryptionAgeX25519](func(_ context.Context) ([]byte, error) {
				return []byte(identity.Recipient().String()), nil
			}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithDecryptionCallbackFunc[DecryptionAgeX25519](func(_ context.Context) ([]byte, error) {
				return []byte(identity.String()), nil
			}),
		)
		require.NoError(t, err)
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
			Attributes: map[string]string{
				"val1": uuid.NewString(),
				"val2": uuid.NewString(),
			},
		}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Save(t.Context(), id, secret))

		fsFiles, err := onlyDirs(root.FS())
		require.NoError(t, err)
		assert.Len(t, fsFiles, 1)

		encodedID := base64.StdEncoding.EncodeToString([]byte(id.String()))
		assert.Equal(t, encodedID, fsFiles[0].Name())

		secretRoot, err := root.OpenRoot(encodedID)
		require.NoError(t, err)

		metadataFile, err := secretRoot.ReadFile(secretfile.MetadataFileName)
		require.NoError(t, err)

		var m map[string]string
		require.NoError(t, json.Unmarshal(metadataFile, &m))

		assert.EqualValues(t, secret.Metadata(), m)

		encryptedFile, err := secretRoot.ReadFile(secretfile.SecretFileName + "pass")
		require.NoError(t, err)

		unencrypted, err := secret.Marshal()
		require.NoError(t, err)
		assert.NotEqual(t, unencrypted, encryptedFile)

		x := s.(*fileStore[*mocks.MockCredential])
		x.registeredDecryptionFunc = []promptCaller{
			DecryptionPassword(func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
		}
		decryptedFile, err := x.decryptSecret(t.Context(), []secretfile.EncryptedSecret{
			{
				KeyType:       secretfile.PasswordKeyType,
				EncryptedData: encryptedFile,
			},
		})

		require.NoError(t, err)
		assert.Equal(t, unencrypted, decryptedFile)
	})

	t.Run("saving the secret again should remove then save", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		masterKey := uuid.NewString()
		identity, err := age.GenerateX25519Identity()
		require.NoError(t, err)

		s, err := New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithLogger(&testLogger{t}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithEncryptionCallbackFunc[EncryptionAgeX25519](func(_ context.Context) ([]byte, error) {
				return []byte(identity.Recipient().String()), nil
			}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithDecryptionCallbackFunc[DecryptionAgeX25519](func(_ context.Context) ([]byte, error) {
				return []byte(identity.String()), nil
			}),
		)
		require.NoError(t, err)
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
			Attributes: map[string]string{
				"val1": uuid.NewString(),
				"val2": uuid.NewString(),
			},
		}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Save(t.Context(), id, secret))

		fsFiles, err := onlyDirs(root.FS())
		require.NoError(t, err)
		assert.Len(t, fsFiles, 1)

		encodedID := base64.StdEncoding.EncodeToString([]byte(id.String()))
		assert.Equal(t, encodedID, fsFiles[0].Name())

		secretRoot, err := root.OpenRoot(fsFiles[0].Name())
		require.NoError(t, err)
		secretFiles, err := fs.ReadDir(secretRoot.FS(), ".")
		require.NoError(t, err)
		assert.Len(t, secretFiles, 3)

		x := s.(*fileStore[*mocks.MockCredential])
		x.registeredEncryptionFuncs = []promptCaller{
			EncryptionAgeX25519(func(_ context.Context) ([]byte, error) {
				return []byte(identity.Recipient().String()), nil
			}),
		}
		require.NoError(t, s.Save(t.Context(), id, secret))

		secretRoot, err = root.OpenRoot(encodedID)
		require.NoError(t, err)
		secretFiles, err = fs.ReadDir(secretRoot.FS(), ".")
		require.NoError(t, err)
		assert.Len(t, secretFiles, 2)
	})

	t.Run("can decrypt with any one of the encryption key", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		masterKey := uuid.NewString()
		identity, err := age.GenerateX25519Identity()
		require.NoError(t, err)

		prv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pub, err := ssh.NewPublicKey(&prv.PublicKey)
		require.NoError(t, err)
		privatePem := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(prv),
		})

		s, err := New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithLogger(&testLogger{t}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithEncryptionCallbackFunc[EncryptionAgeX25519](func(_ context.Context) ([]byte, error) {
				return []byte(identity.Recipient().String()), nil
			}),
			WithEncryptionCallbackFunc[EncryptionSSH](func(_ context.Context) ([]byte, error) {
				return ssh.MarshalAuthorizedKey(pub), nil
			}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
		)
		require.NoError(t, err)
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
			Attributes: map[string]string{
				"val1": uuid.NewString(),
				"val2": uuid.NewString(),
			},
		}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Save(t.Context(), id, secret))

		x := s.(*fileStore[*mocks.MockCredential])
		x.registeredDecryptionFunc = []promptCaller{
			DecryptionAgeX25519(func(_ context.Context) ([]byte, error) {
				return []byte(identity.String()), nil
			}),
		}
		storeSecret, err := s.Get(t.Context(), id)
		require.NoError(t, err)
		assert.Equal(t, secret, storeSecret)

		x.registeredDecryptionFunc = []promptCaller{
			DecryptionSSH(func(_ context.Context) ([]byte, error) {
				return privatePem, nil
			}),
		}
		storeSecret, err = s.Get(t.Context(), id)
		require.NoError(t, err)
		assert.Equal(t, secret, storeSecret)
	})

	t.Run("failure to decrypt will try next decryption key", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		masterKey := uuid.NewString()
		identity, err := age.GenerateX25519Identity()
		require.NoError(t, err)

		prv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pub, err := ssh.NewPublicKey(&prv.PublicKey)
		require.NoError(t, err)

		s, err := New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithLogger(&testLogger{t}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithEncryptionCallbackFunc[EncryptionAgeX25519](func(_ context.Context) ([]byte, error) {
				return []byte(identity.Recipient().String()), nil
			}),
			WithEncryptionCallbackFunc[EncryptionSSH](func(_ context.Context) ([]byte, error) {
				return ssh.MarshalAuthorizedKey(pub), nil
			}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte("not-the-password"), nil
			}),
			WithDecryptionCallbackFunc[DecryptionSSH](func(_ context.Context) ([]byte, error) {
				p, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(p),
				}), nil
			}),
			WithDecryptionCallbackFunc[DecryptionAgeX25519](func(_ context.Context) ([]byte, error) {
				i, err := age.GenerateX25519Identity()
				require.NoError(t, err)
				return []byte(i.String()), nil
			}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
		)
		require.NoError(t, err)
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
			Attributes: map[string]string{
				"val1": uuid.NewString(),
				"val2": uuid.NewString(),
			},
		}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Save(t.Context(), id, secret))

		storeSecret, err := s.Get(t.Context(), id)
		require.NoError(t, err)
		assert.Equal(t, secret, storeSecret)
	})

	t.Run("decryption happens in order specified", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		masterKey := uuid.NewString()
		identity, err := age.GenerateX25519Identity()
		require.NoError(t, err)

		prv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pub, err := ssh.NewPublicKey(&prv.PublicKey)
		require.NoError(t, err)
		privatePem := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(prv),
		})

		s, err := New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithLogger(&testLogger{t}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte(masterKey), nil
			}),
			WithEncryptionCallbackFunc[EncryptionAgeX25519](func(_ context.Context) ([]byte, error) {
				return []byte(identity.Recipient().String()), nil
			}),
			WithEncryptionCallbackFunc[EncryptionSSH](func(_ context.Context) ([]byte, error) {
				return ssh.MarshalAuthorizedKey(pub), nil
			}),
			WithDecryptionCallbackFunc[DecryptionSSH](func(_ context.Context) ([]byte, error) {
				return privatePem, nil
			}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte("not-the-password"), nil
			}),
			WithDecryptionCallbackFunc[DecryptionAgeX25519](func(_ context.Context) ([]byte, error) {
				return []byte(identity.String()), nil
			}),
		)
		require.NoError(t, err)
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
			Attributes: map[string]string{
				"val1": uuid.NewString(),
				"val2": uuid.NewString(),
			},
		}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Save(t.Context(), id, secret))

		storeSecret, err := s.Get(t.Context(), id)
		require.NoError(t, err)
		assert.Equal(t, secret, storeSecret)
	})

	t.Run("an error on encryption callbackFunc is propagated on save", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		encryptError := errors.New("something went wrong inside the encryption callbackFunc")
		s, err := New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithLogger(&testLogger{t}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return nil, encryptError
			}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte("not-the-password"), nil
			}),
		)
		require.NoError(t, err)
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
			Attributes: map[string]string{
				"val1": uuid.NewString(),
				"val2": uuid.NewString(),
			},
		}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		assert.ErrorIs(t, s.Save(t.Context(), id, secret), encryptError)
	})

	t.Run("an error on decryption callbackFunc is propagated on get", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		decryptError := errors.New("something went wrong inside the decryption callbackFunc")
		s, err := New(root,
			func() *mocks.MockCredential {
				return &mocks.MockCredential{}
			},
			WithLogger(&testLogger{t}),
			WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
				return []byte("a-password"), nil
			}),
			WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
				return nil, decryptError
			}),
		)
		require.NoError(t, err)
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
			Attributes: map[string]string{
				"val1": uuid.NewString(),
				"val2": uuid.NewString(),
			},
		}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Save(t.Context(), id, secret))

		_, err = s.Get(t.Context(), id)
		assert.ErrorIs(t, err, decryptError)
	})
}
