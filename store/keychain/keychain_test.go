package keychain

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/mocks"
)

type attributes struct{}

func (a attributes) Metadata() map[string]string {
	return nil
}

func (a attributes) SetMetadata(_ map[string]string) error {
	return errors.New("i am failing on purpose")
}

type mustMarshalError struct {
	attributes
}

var _ store.Secret = &mustMarshalError{}

func (m *mustMarshalError) Marshal() ([]byte, error) {
	return nil, errors.New("i am failing on purpose")
}

func (m *mustMarshalError) Unmarshal([]byte) error {
	return nil
}

type mustUnmarshalError struct {
	attributes
}

var _ store.Secret = &mustUnmarshalError{}

func (m *mustUnmarshalError) Marshal() ([]byte, error) {
	return []byte("eeyyy"), nil
}

func (m *mustUnmarshalError) Unmarshal([]byte) error {
	return errors.New("i am failing on purpose")
}

func setupKeychain(t *testing.T, secretFactory func() store.Secret) store.Store {
	t.Helper()
	if secretFactory == nil {
		secretFactory = func() store.Secret {
			return &mocks.MockCredential{}
		}
	}

	ks, err := New("com.test.test", "test", secretFactory)
	require.NoError(t, err)
	return ks
}

func TestKeychain(t *testing.T) {
	t.Run("save credentials", func(t *testing.T) {
		ks := setupKeychain(t, nil)
		id := store.MustParseID("com.test.test/test/bob")
		creds := &mocks.MockCredential{
			Username: "bob",
			Password: "bob-password",
		}
		t.Cleanup(func() {
			require.NoError(t, ks.Delete(t.Context(), id))
		})
		require.NoError(t, ks.Save(t.Context(), id, creds))
	})

	t.Run("get credential", func(t *testing.T) {
		ks := setupKeychain(t, nil)
		id := store.MustParseID("com.test.test/test/bob")
		creds := &mocks.MockCredential{
			Username: "bob",
			Password: "bob-password",
		}
		t.Cleanup(func() {
			require.NoError(t, ks.Delete(t.Context(), id))
		})
		require.NoError(t, ks.Save(t.Context(), id, creds))
		secret, err := ks.Get(t.Context(), id)
		require.NoError(t, err)

		actual, ok := secret.(*mocks.MockCredential)
		require.True(t, ok)
		// we haven't set any attributes, but the underlying store might've
		// since this is store specific, let's drop the attributes in this
		// test
		actual.Attributes = nil

		expected := creds
		assert.EqualValues(t, expected, actual)
	})

	t.Run("list all credentials", func(t *testing.T) {
		ks := setupKeychain(t, nil)

		moreCreds := map[store.ID]*mocks.MockCredential{
			store.MustParseID("com.test.test/test/bob"): {
				Username: "bob",
				Password: "bob-password",
				Attributes: map[string]string{
					"color": "blue",
					"game":  "elden ring",
				},
			},
			store.MustParseID("com.test.test/test/jeff"): {
				Username: "jeff",
				Password: "jeff-password",
			},
			store.MustParseID("com.test.test/test/pete"): {
				Username: "pete",
				Password: "pete-password",
			},
		}
		t.Cleanup(func() {
			for id := range moreCreds {
				require.NoError(t, ks.Delete(t.Context(), id))
			}
		})

		for id, anotherCred := range moreCreds {
			require.NoError(t, ks.Save(t.Context(), id, anotherCred))
		}
		secrets, err := ks.GetAllMetadata(t.Context())
		require.NoError(t, err)
		assert.Len(t, secrets, 3)

		actual := make(map[store.ID]*mocks.MockCredential)
		for k, v := range secrets {
			actual[k] = v.(*mocks.MockCredential)
		}

		expected := moreCreds
		for _, v := range expected {
			// listing credentials from the store won't retrieve the actual
			// credentials, only the metadata.
			// That is why we set username and password to empty
			v.Username = ""
			v.Password = ""
			if v.Attributes == nil {
				v.Attributes = make(map[string]string)
			}
		}
		assert.EqualValues(t, expected, actual)
	})

	t.Run("filter credentials", func(t *testing.T) {
		ks := setupKeychain(t, nil)
		moreCreds := map[store.ID]*mocks.MockCredential{
			store.MustParseID("com.test.test/test/bob"): {
				Username: "bob",
				Password: "bob-password",
				Attributes: map[string]string{
					"role":     "admin",
					"favcolor": "green",
				},
			},
			store.MustParseID("com.test.test/test/jeff"): {
				Username: "jeff",
				Password: "jeff-password",
			},
			store.MustParseID("com.test.test/test/pete"): {
				Username: "pete",
				Password: "pete-password",
				Attributes: map[string]string{
					"role":     "maintainer",
					"favcolor": "green",
				},
			},
			store.MustParseID("com.test.test2/test2/bob"): {
				Username: "bob",
				Password: "bob-password",
				Attributes: map[string]string{
					"role":     "admin",
					"favcolor": "green",
				},
			},
		}
		for id, anotherCred := range moreCreds {
			require.NoError(t, ks.Save(t.Context(), id, anotherCred))
		}

		t.Cleanup(func() {
			for id := range moreCreds {
				assert.NoError(t, ks.Delete(t.Context(), id))
			}
		})

		t.Run("can use recursive pattern", func(t *testing.T) {
			actual, err := ks.Filter(t.Context(), store.MustParsePattern("com.test.test/**"))
			require.NoError(t, err)
			assert.Len(t, actual, 3)
		})

		t.Run("can use subset pattern", func(t *testing.T) {
			actual, err := ks.Filter(t.Context(), store.MustParsePattern("com.test.test/test/*"))
			require.NoError(t, err)
			assert.Len(t, actual, 3)
		})

		t.Run("can use serviceName only in pattern", func(t *testing.T) {
			actual, err := ks.Filter(t.Context(), store.MustParsePattern("*/test/*"))
			require.NoError(t, err)
			assert.Len(t, actual, 3)
		})

		t.Run("can match on only username in pattern", func(t *testing.T) {
			result, err := ks.Filter(t.Context(), store.MustParsePattern("**/bob"))
			require.NoError(t, err)
			assert.Len(t, result, 2)
			actual := make(map[store.ID]*mocks.MockCredential)
			for k, v := range result {
				actual[k] = v.(*mocks.MockCredential)
			}
			assert.Len(t, actual, 2)
			expected := make(map[store.ID]*mocks.MockCredential)
			expected[store.MustParseID("com.test.test/test/bob")] = moreCreds[store.MustParseID("com.test.test/test/bob")]
			expected[store.MustParseID("com.test.test2/test2/bob")] = moreCreds[store.MustParseID("com.test.test2/test2/bob")]
			assert.EqualValues(t, expected, actual)
		})

		t.Run("exact id match should still return exactly one secret", func(t *testing.T) {
			actual, err := ks.Filter(t.Context(), store.MustParsePattern("com.test.test/test/pete"))
			require.NoError(t, err)
			assert.Len(t, actual, 1)
			_, ok := actual[store.MustParseID("com.test.test/test/pete")]
			assert.True(t, ok)
		})
	})

	t.Run("delete credential", func(t *testing.T) {
		ks := setupKeychain(t, nil)
		id := store.MustParseID("com.test.test/test/bob")
		creds := &mocks.MockCredential{
			Username: "bob",
			Password: "bob-password",
		}
		require.NoError(t, ks.Save(t.Context(), id, creds))
		require.NoError(t, ks.Delete(t.Context(), id))
		_, err := ks.Get(t.Context(), id)
		require.ErrorIs(t, err, store.ErrCredentialNotFound)
	})

	t.Run("delete non-existent credential", func(t *testing.T) {
		ks := setupKeychain(t, nil)
		id := store.MustParseID("com.test.test/test/does-not-exist")
		require.NoError(t, ks.Delete(t.Context(), id))
	})

	t.Run("marshal error on save", func(t *testing.T) {
		kc := setupKeychain(t, nil)
		id, err := store.ParseID("something/will/fail")
		require.NoError(t, err)
		require.ErrorContains(t, kc.Save(t.Context(), id, &mustMarshalError{}), "i am failing on purpose")
	})

	t.Run("unmarshal error on get", func(t *testing.T) {
		kc := setupKeychain(t, func() store.Secret {
			return &mustUnmarshalError{}
		})
		id, err := store.ParseID("something/will/fail")
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, kc.Delete(t.Context(), id))
		})
		require.NoError(t, kc.Save(t.Context(), id, &mustUnmarshalError{}))
		_, err = kc.Get(t.Context(), id)
		require.ErrorContains(t, err, "i am failing on purpose")
	})

	t.Run("set metadata error on getAllMetadata", func(t *testing.T) {
		kc := setupKeychain(t, func() store.Secret {
			return &mustUnmarshalError{}
		})
		id, err := store.ParseID("something/will/fail")
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, kc.Delete(t.Context(), id))
		})
		require.NoError(t, kc.Save(t.Context(), id, &mustUnmarshalError{}))
		_, err = kc.GetAllMetadata(t.Context())
		require.ErrorContains(t, err, "i am failing on purpose")
	})
}

func TestSafelySetID(t *testing.T) {
	t.Run("can set id in attributes", func(t *testing.T) {
		attributes := map[string]string{
			"color":              "blue",
			"game":               "elden ring",
			"id":                 "avoid clash",
			"x_already-prefixed": "prefixed",
		}
		safelySetID(store.MustParseID("username"), attributes)
		assert.EqualValues(t, map[string]string{
			"color":              "blue",
			"game":               "elden ring",
			"x_already-prefixed": "prefixed",
			"x_id":               "avoid clash",
			secretIDKey:          "username",
		}, attributes)
	})
	t.Run("can clean id from attributes", func(t *testing.T) {
		attributes := map[string]string{
			"x_color":            "blue",
			"x_game":             "elden ring",
			"x_already-prefixed": "prefixed",
			"x_id":               "avoid clash",
			secretIDKey:          "username",
		}
		safelyCleanMetadata(attributes)
		assert.EqualValues(t, map[string]string{
			"color":            "blue",
			"game":             "elden ring",
			"already-prefixed": "prefixed",
			"id":               "avoid clash",
		}, attributes)
	})
}

func TestSafelySetMetadata(t *testing.T) {
	var (
		serviceGroup = "com.test.test"
		serviceName  = "test"
	)

	t.Run("avoid clashing by adding prefix", func(t *testing.T) {
		attributes := map[string]string{
			"color":              "blue",
			"game":               "elden ring",
			"id":                 "avoid clash",
			"x_already-prefixed": "prefixed",
		}
		safelySetMetadata(serviceGroup, serviceName, attributes)
		assert.EqualValues(t, map[string]string{
			"x_color":              "blue",
			"x_game":               "elden ring",
			"x_id":                 "avoid clash",
			"x_x_already-prefixed": "prefixed",
			serviceGroupKey:        "com.test.test",
			serviceNameKey:         "test",
		}, attributes)
	})

	t.Run("empty keys will also be prefixed", func(t *testing.T) {
		attributes := map[string]string{
			"": "something",
		}
		safelySetMetadata(serviceGroup, serviceName, attributes)
		assert.EqualValues(t, map[string]string{
			"x_":            "something",
			serviceGroupKey: "com.test.test",
			serviceNameKey:  "test",
		}, attributes)
	})

	t.Run("empty map will get internal data added", func(t *testing.T) {
		attributes := map[string]string{}
		safelySetMetadata(serviceGroup, serviceName, attributes)
		assert.EqualValues(t, map[string]string{
			serviceGroupKey: "com.test.test",
			serviceNameKey:  "test",
		}, attributes)
	})

	t.Run("empty id parameter won't add the id attribute", func(t *testing.T) {
		attributes := map[string]string{}
		safelySetMetadata(serviceGroup, serviceName, attributes)
		assert.EqualValues(t, map[string]string{
			serviceGroupKey: "com.test.test",
			serviceNameKey:  "test",
		}, attributes)
	})
}

func TestSafelyCleanMetadata(t *testing.T) {
	t.Run("can remove prefix and internal metadata", func(t *testing.T) {
		attributes := map[string]string{
			"x_color":              "blue",
			"x_game":               "elden ring",
			"x_id":                 "avoid clash",
			"x_x_already-prefixed": "prefixed",
			secretIDKey:            "username",
			serviceGroupKey:        "com.test.test",
			serviceNameKey:         "test",
		}
		safelyCleanMetadata(attributes)
		assert.EqualValues(t, map[string]string{
			"color":              "blue",
			"game":               "elden ring",
			"x_already-prefixed": "prefixed",
			"id":                 "avoid clash",
		}, attributes)
	})

	t.Run("empty map won't cause any panics", func(t *testing.T) {
		attributes := make(map[string]string)
		safelyCleanMetadata(attributes)
		assert.Empty(t, attributes)
	})

	t.Run("internal attributes are always removed", func(t *testing.T) {
		attributes := map[string]string{
			secretIDKey:     "username",
			serviceGroupKey: "com.test.test",
			serviceNameKey:  "test",
		}
		safelyCleanMetadata(attributes)
		assert.Empty(t, attributes)
	})

	t.Run("underlying store attributes are always removed", func(t *testing.T) {
		attributes := map[string]string{
			secretIDKey:     "username",
			serviceGroupKey: "com.test.test",
			serviceNameKey:  "test",
			"x_something":   "something",
			// xdg:scheme is added by the underlying linux keychain after we
			// have prefixed key's with 'x_'
			"xdg:scheme": "org.freedesktop.Secret.Generic",
		}
		safelyCleanMetadata(attributes)
		assert.EqualValues(t, map[string]string{
			"something": "something",
		}, attributes)
	})
}
