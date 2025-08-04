//go:build darwin && cgo

package keychain

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/mocks"
)

func TestMacosKeychain(t *testing.T) {
	secret := &mocks.MockCredential{
		Username: uuid.NewString(),
		Password: "bob2",
	}
	var (
		serviceName  = uuid.NewString()
		serviceGroup = "test.testing." + uuid.NewString()
		id           = store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())
	)
	store := keychainStore[*mocks.MockCredential]{
		serviceGroup: "test.testing." + uuid.NewString(),
		serviceName:  uuid.NewString(),
		factory: func() *mocks.MockCredential {
			return &mocks.MockCredential{}
		},
	}

	t.Run("secret can have no attributes", func(t *testing.T) {
		t.Cleanup(func() {
			assert.NoError(t, store.Delete(context.Background(), id))
		})
		require.NoError(t, store.Save(t.Context(), id, secret))

		storeSecret, err := store.Get(t.Context(), id)
		require.NoError(t, err)
		assert.Empty(t, storeSecret.Metadata())
	})

	t.Run("secret can store large attributes", func(t *testing.T) {
		t.Cleanup(func() {
			assert.NoError(t, store.Delete(context.Background(), id))
		})
		large := bytes.Repeat([]byte{'a'}, 1024*1024)
		secret.Attributes = map[string]string{
			"large": string(large),
			"small": "eyy",
		}
		require.NoError(t, store.Save(t.Context(), id, secret))

		storeSecret, err := store.Get(t.Context(), id)
		require.NoError(t, err)
		assert.EqualValues(t, secret.Attributes, storeSecret.Metadata())
	})
}

func TestConvertAttributes(t *testing.T) {
	t.Run("can convert attributes map into map of any", func(t *testing.T) {
		attributes := map[string]any{
			"game":  "elden ring",
			"color": "blue",
		}
		converted, err := convertAttributes(attributes)
		assert.NoError(t, err)
		assert.IsTypef(t, map[string]string{}, converted, "expected type after conversion to be map[string]string")
		assert.EqualValues(t, map[string]string{
			"game":  "elden ring",
			"color": "blue",
		}, converted)
	})
	t.Run("should error when a value has a non-string type", func(t *testing.T) {
		attributes := map[string]any{
			"score": 20,
			"color": "blue",
		}
		converted, err := convertAttributes(attributes)
		assert.ErrorContains(t, err, "unsupported type")
		assert.Nil(t, converted)
	})
	t.Run("nil attributes map should return empty map with no error", func(t *testing.T) {
		var attributes map[string]any
		converted, err := convertAttributes(attributes)
		assert.NoError(t, err)
		assert.Empty(t, converted)
	})
}
