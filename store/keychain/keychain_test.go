package keychain

import (
	"context"
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
		id := store.ID("com.test.test/test/bob")
		require.NoError(t, id.Valid())
		creds := &mocks.MockCredential{
			Username: "bob",
			Password: "bob-password",
		}
		t.Cleanup(func() {
			require.NoError(t, ks.Delete(context.Background(), id))
		})
		require.NoError(t, ks.Save(t.Context(), id, creds))
	})

	t.Run("get credential", func(t *testing.T) {
		ks := setupKeychain(t, nil)
		id := store.ID("com.test.test/test/bob")
		creds := &mocks.MockCredential{
			Username: "bob",
			Password: "bob-password",
		}
		t.Cleanup(func() {
			require.NoError(t, ks.Delete(context.Background(), id))
		})
		require.NoError(t, ks.Save(t.Context(), id, creds))
		require.NoError(t, id.Valid())
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
			"com.test.test/test/bob": {
				Username: "bob",
				Password: "bob-password",
				Attributes: map[string]string{
					"color": "blue",
					"game":  "elden ring",
				},
			},
			"com.test.test/test/jeff": {
				Username: "jeff",
				Password: "jeff-password",
			},
			"com.test.test/test/pete": {
				Username: "pete",
				Password: "pete-password",
			},
		}
		t.Cleanup(func() {
			for id := range moreCreds {
				require.NoError(t, ks.Delete(context.Background(), id))
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

	t.Run("delete credential", func(t *testing.T) {
		ks := setupKeychain(t, nil)
		id := store.ID("com.test.test/test/bob")
		require.NoError(t, id.Valid())
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
		id := store.ID("com.test.test/test/does-not-exist")
		require.NoError(t, id.Valid())
		require.NoError(t, ks.Delete(t.Context(), id))
	})

	t.Run("invalid ID", func(t *testing.T) {
		id := store.ID("completely*&@#$@invalid")
		kc := setupKeychain(t, nil)

		operations := []string{"save", "get", "delete"}

		for _, op := range operations {
			t.Run(op, func(t *testing.T) {
				var err error
				switch op {
				case "save":
					err = kc.Save(t.Context(), id, nil)
				case "delete":
					err = kc.Delete(t.Context(), id)
				case "get":
					_, err = kc.Get(t.Context(), id)
				}
				require.ErrorContains(t, err, "invalid identifier")
			})
		}
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
			require.NoError(t, kc.Delete(context.Background(), id))
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
			require.NoError(t, kc.Delete(context.Background(), id))
		})
		require.NoError(t, kc.Save(t.Context(), id, &mustUnmarshalError{}))
		_, err = kc.GetAllMetadata(t.Context())
		require.ErrorContains(t, err, "i am failing on purpose")
	})
}

func TestSafelySetMetadata(t *testing.T) {
	kc := &keychainStore[*mocks.MockCredential]{
		serviceGroup: "com.test.test",
		serviceName:  "test",
	}

	t.Run("avoid clashing by adding prefix", func(t *testing.T) {
		attributes := map[string]string{
			"color":              "blue",
			"game":               "elden ring",
			"id":                 "avoid clash",
			"x_already-prefixed": "prefixed",
		}
		kc.safelySetMetadata("username", attributes)
		assert.EqualValues(t, map[string]string{
			"x_color":              "blue",
			"x_game":               "elden ring",
			"x_id":                 "avoid clash",
			"x_x_already-prefixed": "prefixed",
			secretIDKey:            "username",
			serviceGroupKey:        "com.test.test",
			serviceNameKey:         "test",
		}, attributes)
	})

	t.Run("empty keys will also be prefixed", func(t *testing.T) {
		attributes := map[string]string{
			"": "something",
		}
		kc.safelySetMetadata("", attributes)
		assert.EqualValues(t, map[string]string{
			"x_":            "something",
			serviceGroupKey: "com.test.test",
			serviceNameKey:  "test",
		}, attributes)
	})

	t.Run("empty map will get internal data added", func(t *testing.T) {
		attributes := map[string]string{}
		kc.safelySetMetadata("username", attributes)
		assert.EqualValues(t, map[string]string{
			secretIDKey:     "username",
			serviceGroupKey: "com.test.test",
			serviceNameKey:  "test",
		}, attributes)
	})

	t.Run("empty id parameter won't add the id attribute", func(t *testing.T) {
		attributes := map[string]string{}
		kc.safelySetMetadata("", attributes)
		assert.EqualValues(t, map[string]string{
			serviceGroupKey: "com.test.test",
			serviceNameKey:  "test",
		}, attributes)
	})
}

func TestSafelyCleanMetadata(t *testing.T) {
	kc := &keychainStore[*mocks.MockCredential]{
		serviceGroup: "com.test.test",
		serviceName:  "test",
	}
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
		kc.safelyCleanMetadata(attributes)
		assert.EqualValues(t, map[string]string{
			"color":              "blue",
			"game":               "elden ring",
			"x_already-prefixed": "prefixed",
			"id":                 "avoid clash",
		}, attributes)
	})
	t.Run("empty map won't cause any panics", func(t *testing.T) {
		attributes := make(map[string]string)
		kc.safelyCleanMetadata(attributes)
		assert.Empty(t, attributes)
	})

	t.Run("internal attributes are always removed", func(t *testing.T) {
		attributes := map[string]string{
			secretIDKey:     "username",
			serviceGroupKey: "com.test.test",
			serviceNameKey:  "test",
		}
		kc.safelyCleanMetadata(attributes)
		assert.Empty(t, attributes)
	})
}

func TestInternalMetadata(t *testing.T) {
	kc := &keychainStore[*mocks.MockCredential]{
		serviceGroup: "com.test.test",
		serviceName:  "test",
	}

	t.Run("metadata can safely be set and cleaned afterwards", func(t *testing.T) {
		attributes := map[string]string{
			"color":              "blue",
			"game":               "elden ring",
			"id":                 "avoid clash",
			"x_already-prefixed": "prefixed",
		}
		kc.safelySetMetadata("username", attributes)
		assert.EqualValues(t, map[string]string{
			"x_color":              "blue",
			"x_game":               "elden ring",
			"x_id":                 "avoid clash",
			"x_x_already-prefixed": "prefixed",
			secretIDKey:            "username",
			serviceGroupKey:        "com.test.test",
			serviceNameKey:         "test",
		}, attributes)

		kc.safelyCleanMetadata(attributes)
		assert.EqualValues(t, map[string]string{
			"color":              "blue",
			"game":               "elden ring",
			"x_already-prefixed": "prefixed",
			"id":                 "avoid clash",
		}, attributes)
	})
}
