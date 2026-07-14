// Copyright 2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	"strconv"
	"strings"
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
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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

	t.Run("upsert inserts when credential does not exist", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		masterKey := uuid.NewString()
		s, err := New(root,
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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
		}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Upsert(t.Context(), id, secret))

		storeSecret, err := s.Get(t.Context(), id)
		require.NoError(t, err)
		assert.EqualValues(t, secret, storeSecret)
	})

	t.Run("upsert overwrites an existing credential", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		masterKey := uuid.NewString()
		s, err := New(root,
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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

		original := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
		}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Save(t.Context(), id, original))

		updated := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
		}
		require.NoError(t, s.Upsert(t.Context(), id, updated))

		storeSecret, err := s.Get(t.Context(), id)
		require.NoError(t, err)
		assert.EqualValues(t, updated, storeSecret)
	})

	t.Run("an error on encryption callbackFunc is propagated on save", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		encryptError := errors.New("something went wrong inside the encryption callbackFunc")
		s, err := New(root,
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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
			func(_ context.Context, _ store.ID) *mocks.MockCredential {
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

// scryptStanzaWorkFactor extracts the logN work factor recorded in the scrypt
// stanza of an age file header. The header is ASCII; the scrypt stanza has the
// form "-> scrypt <base64 salt> <logN>".
func scryptStanzaWorkFactor(t *testing.T, ageFile []byte) int {
	t.Helper()
	for line := range strings.SplitSeq(string(ageFile), "\n") {
		if !strings.HasPrefix(line, "-> scrypt ") {
			continue
		}
		fields := strings.Fields(line)
		logN, err := strconv.Atoi(fields[len(fields)-1])
		require.NoError(t, err)
		return logN
	}
	t.Fatal("no scrypt stanza found in age header")
	return 0
}

// newTempRoot opens an os.Root over a per-test temporary directory and closes
// it on cleanup.
func newTempRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, root.Close())
	})
	return root
}

// newPasswordStore builds a posixage store over root that encrypts and decrypts
// with a single password, plus any extra options.
func newPasswordStore(t *testing.T, root *os.Root, password string, opts ...Options) store.Store {
	t.Helper()
	base := []Options{
		WithLogger(&testLogger{t}),
		WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
			return []byte(password), nil
		}),
		WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
			return []byte(password), nil
		}),
	}
	s, err := New(root,
		func(_ context.Context, _ store.ID) *mocks.MockCredential {
			return &mocks.MockCredential{}
		},
		append(base, opts...)...,
	)
	require.NoError(t, err)
	return s
}

// readPassSecret reads the raw password-encrypted age file for id.
func readPassSecret(t *testing.T, root *os.Root, id store.ID) []byte {
	t.Helper()
	encodedID := base64.StdEncoding.EncodeToString([]byte(id.String()))
	secretRoot, err := root.OpenRoot(encodedID)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, secretRoot.Close())
	})
	data, err := secretRoot.ReadFile(secretfile.SecretFileName + "pass")
	require.NoError(t, err)
	return data
}

func TestScryptWorkFactor(t *testing.T) {
	// Use a low work factor so the KDF stays fast in tests; the default (18) is
	// tuned to take ~1s per operation.
	const workFactor = 10

	t.Run("records the configured work factor in the header", func(t *testing.T) {
		password := uuid.NewString()
		root := newTempRoot(t)
		s := newPasswordStore(t, root, password, WithScryptWorkFactor(workFactor))

		secret := &mocks.MockCredential{Username: uuid.NewString(), Password: uuid.NewString()}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Save(t.Context(), id, secret))

		encryptedFile := readPassSecret(t, root, id)
		assert.Equal(t, workFactor, scryptStanzaWorkFactor(t, encryptedFile))

		// Round-trips with the same store.
		got, err := s.Get(t.Context(), id)
		require.NoError(t, err)
		assert.EqualValues(t, secret, got)
	})

	t.Run("defaults to the age work factor when unset", func(t *testing.T) {
		password := uuid.NewString()
		root := newTempRoot(t)
		s := newPasswordStore(t, root, password)

		secret := &mocks.MockCredential{Username: uuid.NewString(), Password: uuid.NewString()}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, s.Save(t.Context(), id, secret))

		encryptedFile := readPassSecret(t, root, id)
		// age's NewScryptRecipient default is logN=18.
		assert.Equal(t, 18, scryptStanzaWorkFactor(t, encryptedFile))
	})

	t.Run("work factor is self-describing across stores", func(t *testing.T) {
		// A file written with a custom work factor must decrypt on a store that
		// has no work-factor option configured: the factor is read from the
		// header, not from store configuration.
		password := uuid.NewString()
		root := newTempRoot(t)
		writer := newPasswordStore(t, root, password, WithScryptWorkFactor(workFactor))

		secret := &mocks.MockCredential{Username: uuid.NewString(), Password: uuid.NewString()}
		id := secrets.MustParseID("test/something/" + uuid.NewString())
		require.NoError(t, writer.Save(t.Context(), id, secret))

		// A separate store with no work-factor option configured.
		reader := newPasswordStore(t, root, password)

		got, err := reader.Get(t.Context(), id)
		require.NoError(t, err)
		assert.EqualValues(t, secret, got)
	})

	t.Run("rejects out-of-range work factors", func(t *testing.T) {
		root := newTempRoot(t)

		for _, logN := range []int{0, -1, secretfile.MaxScryptWorkFactor + 1} {
			_, err := New(root,
				func(_ context.Context, _ store.ID) *mocks.MockCredential {
					return &mocks.MockCredential{}
				},
				WithEncryptionCallbackFunc[EncryptionPassword](func(_ context.Context) ([]byte, error) {
					return []byte("a-password"), nil
				}),
				WithDecryptionCallbackFunc[DecryptionPassword](func(_ context.Context) ([]byte, error) {
					return []byte("a-password"), nil
				}),
				WithScryptWorkFactor(logN),
			)
			assert.Error(t, err, "logN=%d should be rejected", logN)
		}
	})
}

// TestScryptWorkFactorMigration documents how an existing secret's scrypt work
// factor is migrated: there is no transparent on-read migration, but because
// Save/Upsert re-encrypts the whole secret, re-writing a secret with a store
// configured for a different work factor migrates the stored file to that
// factor while preserving the plaintext. The factor moves in both directions.
func TestScryptWorkFactorMigration(t *testing.T) {
	password := uuid.NewString()
	root := newTempRoot(t)

	secret := &mocks.MockCredential{
		Username: uuid.NewString(),
		Password: uuid.NewString(),
		Attributes: map[string]string{
			"val1": uuid.NewString(),
		},
	}
	id := secrets.MustParseID("test/something/" + uuid.NewString())

	// Seed the secret with the age default (logN=18), simulating data written
	// by a build that never configured a work factor.
	initial := newPasswordStore(t, root, password)
	require.NoError(t, initial.Save(t.Context(), id, secret))
	require.Equal(t, 18, scryptStanzaWorkFactor(t, readPassSecret(t, root, id)))

	// Each step re-writes the same secret with a store configured for a
	// different work factor: default -> lower -> higher.
	steps := []struct {
		name       string
		workFactor int
	}{
		{"migrate to a lower work factor", 8},
		{"migrate to a higher work factor", 14},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			s := newPasswordStore(t, root, password, WithScryptWorkFactor(step.workFactor))

			// The old file (written with the previous factor) must still decrypt
			// on this store, since the factor is read from the file header.
			got, err := s.Get(t.Context(), id)
			require.NoError(t, err)
			assert.EqualValues(t, secret, got)

			// Re-writing migrates the stored file to the new work factor.
			require.NoError(t, s.Upsert(t.Context(), id, secret))
			assert.Equal(t, step.workFactor, scryptStanzaWorkFactor(t, readPassSecret(t, root, id)))

			// The migrated file still decrypts to the same plaintext.
			got, err = s.Get(t.Context(), id)
			require.NoError(t, err)
			assert.EqualValues(t, secret, got)
		})
	}
}
