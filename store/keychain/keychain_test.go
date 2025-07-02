package keychain

import (
	"errors"
	"testing"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/mocks"
	"github.com/stretchr/testify/require"
)

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
			require.NoError(t, ks.Delete(t.Context(), id))
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
			require.NoError(t, ks.Delete(t.Context(), id))
		})
		require.NoError(t, ks.Save(t.Context(), id, creds))
		require.NoError(t, id.Valid())
		secret, err := ks.Get(t.Context(), id)
		require.NoError(t, err)

		actual, ok := secret.(*mocks.MockCredential)
		require.True(t, ok)

		expected := creds
		require.EqualValues(t, expected, actual)
	})

	t.Run("list all credentials", func(t *testing.T) {
		ks := setupKeychain(t, nil)

		moreCreds := map[store.ID]*mocks.MockCredential{
			"com.test.test/test/bob": {
				Username: "bob",
				Password: "bob-password",
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
				require.NoError(t, ks.Delete(t.Context(), id))
			}
		})

		for id, anotherCred := range moreCreds {
			require.NoError(t, ks.Save(t.Context(), id, anotherCred))
		}
		secrets, err := ks.GetAll(t.Context())
		require.NoError(t, err)

		actual := make(map[store.ID]*mocks.MockCredential)
		for id, s := range secrets {
			actual[id] = s.(*mocks.MockCredential)
		}
		require.Len(t, actual, 3)

		expected := moreCreds
		require.Equal(t, expected, actual)
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
			require.NoError(t, kc.Delete(t.Context(), id))
		})
		require.NoError(t, kc.Save(t.Context(), id, &mustUnmarshalError{}))
		_, err = kc.Get(t.Context(), id)
		require.ErrorContains(t, err, "i am failing on purpose")
	})

	t.Run("unmarshal error on getAll", func(t *testing.T) {
		kc := setupKeychain(t, func() store.Secret {
			return &mustUnmarshalError{}
		})
		id, err := store.ParseID("something/will/fail")
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, kc.Delete(t.Context(), id))
		})
		require.NoError(t, kc.Save(t.Context(), id, &mustUnmarshalError{}))
		_, err = kc.GetAll(t.Context())
		require.ErrorContains(t, err, "i am failing on purpose")
	})
}

type mustMarshalError struct{}

// Marshal implements store.Secret.
func (m *mustMarshalError) Marshal() ([]byte, error) {
	return nil, errors.New("i am failing on purpose")
}

// Unmarshal implements store.Secret.
func (m *mustMarshalError) Unmarshal(data []byte) error {
	return nil
}

var _ store.Secret = &mustMarshalError{}

type mustUnmarshalError struct{}

// Marshal implements store.Secret.
func (m *mustUnmarshalError) Marshal() ([]byte, error) {
	return []byte("eeyyy"), nil
}

// Unmarshal implements store.Secret.
func (m *mustUnmarshalError) Unmarshal(data []byte) error {
	return errors.New("i am failing on purpose")
}

var _ store.Secret = &mustUnmarshalError{}
