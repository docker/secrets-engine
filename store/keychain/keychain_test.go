package keychain

import (
	"testing"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/mocks"
	"github.com/stretchr/testify/require"
)

func setupKeychain(t *testing.T) store.Store {
	t.Helper()

	ks, err := New("com.test.test", "test",
		func() *mocks.MockCredential {
			return &mocks.MockCredential{}
		},
	)
	require.NoError(t, err)
	return ks
}

func TestKeychain(t *testing.T) {
	t.Run("save credentials", func(t *testing.T) {
		ks := setupKeychain(t)
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
		ks := setupKeychain(t)
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
		ks := setupKeychain(t)

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
		ks := setupKeychain(t)
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
		ks := setupKeychain(t)
		id := store.ID("com.test.test/test/does-not-exist")
		require.NoError(t, id.Valid())
		require.NoError(t, ks.Delete(t.Context(), id))
	})
}
