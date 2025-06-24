package keychain

import (
	"context"
	"maps"
	"testing"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/mocks"
	"github.com/stretchr/testify/require"
)

func TestKeychain(t *testing.T) {
	mainCtx, mainCtxCancel := context.WithCancel(context.Background())
	t.Cleanup(mainCtxCancel)

	ks, err := New("com.test.test", "test",
		func() *mocks.MockCredential {
			return &mocks.MockCredential{}
		},
	)
	require.NoError(t, err)

	t.Run("save credentials", func(t *testing.T) {
		ctx, cancel := context.WithCancel(mainCtx)
		t.Cleanup(cancel)

		id := store.ID("com.test.test/test/bob")
		require.NoError(t, id.Valid())
		creds := &mocks.MockCredential{
			Username: "bob",
			Password: "bob-password",
		}
		require.NoError(t, ks.Save(ctx, id, creds))
	})

	t.Run("get credential", func(t *testing.T) {
		ctx, cancel := context.WithCancel(mainCtx)
		t.Cleanup(cancel)

		id := store.ID("com.test.test/test/bob")
		require.NoError(t, id.Valid())
		secret, err := ks.Get(ctx, id)
		require.NoError(t, err)

		actual, ok := secret.(*mocks.MockCredential)
		require.True(t, ok)

		expected := &mocks.MockCredential{
			Username: "bob",
			Password: "bob-password",
		}
		require.EqualValues(t, expected, actual)
	})

	t.Run("list all credentials", func(t *testing.T) {
		ctx, cancel := context.WithCancel(mainCtx)
		t.Cleanup(cancel)

		moreCreds := map[store.ID]*mocks.MockCredential{
			"com.test.test/test/jeff": {
				Username: "jeff",
				Password: "jeff-password",
			},
			"com.test.test/test/pete": {
				Username: "pete",
				Password: "pete-password",
			},
		}

		for id, anotherCred := range moreCreds {
			require.NoError(t, ks.Save(ctx, id, anotherCred))
		}
		secrets, err := ks.GetAll(ctx)
		require.NoError(t, err)

		actual := make(map[store.ID]*mocks.MockCredential)
		for id, s := range secrets {
			actual[id] = s.(*mocks.MockCredential)
		}
		require.Len(t, actual, 3)

		expected := map[store.ID]*mocks.MockCredential{
			"com.test.test/test/bob": {
				Username: "bob",
				Password: "bob-password",
			},
		}
		maps.Copy(expected, moreCreds)
		require.Len(t, expected, 3)
		require.Equal(t, expected, actual)
	})

	t.Run("delete credential", func(t *testing.T) {
		ctx, cancel := context.WithCancel(mainCtx)
		t.Cleanup(cancel)

		id := store.ID("com.test.test/test/bob")
		require.NoError(t, id.Valid())
		require.NoError(t, ks.Delete(ctx, id))
		_, err := ks.Get(ctx, id)
		require.ErrorIs(t, err, store.ErrCredentialNotFound)
	})
}
