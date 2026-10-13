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
	kc "github.com/docker/secrets-engine/store/keychain/internal/go-keychain"
	"github.com/docker/secrets-engine/store/mocks"
)

func TestMacosKeychain(t *testing.T) {
	var (
		serviceName  = uuid.NewString()
		serviceGroup = "com.test.testing"
	)
	keychainStore := keychainStore[*mocks.MockCredential]{
		serviceGroup: serviceGroup,
		serviceName:  serviceName,
		factory: func(_ context.Context, _ store.ID) *mocks.MockCredential {
			return &mocks.MockCredential{}
		},
	}

	ids := []string{
		serviceGroup + "/" + serviceName + "/" + uuid.NewString(),
		serviceGroup + "/" + serviceName + "/" + uuid.NewString(),
		serviceGroup + "/" + serviceName + "/" + uuid.NewString(),
	}
	t.Cleanup(func() {
		for _, id := range ids {
			assert.NoError(t, keychainStore.Delete(t.Context(), store.MustParseID(id)))
		}
	})
	for _, id := range ids {
		assert.NoError(t, keychainStore.Save(t.Context(), store.MustParseID(id), &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: uuid.NewString(),
			Attributes: map[string]string{
				"color": "purple",
				"game":  "unknown",
			},
		}))
	}

	t.Run("can store secret that has no attribute", func(t *testing.T) {
		id := store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())

		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: "bob2",
		}
		t.Cleanup(func() {
			assert.NoError(t, keychainStore.Delete(t.Context(), id))
		})
		require.NoError(t, keychainStore.Save(t.Context(), id, secret))
		storeSecret, err := keychainStore.Get(t.Context(), id)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]string{}, storeSecret.Metadata())
	})

	t.Run("can store large attributes", func(t *testing.T) {
		id := store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())
		t.Cleanup(func() {
			assert.NoError(t, keychainStore.Delete(t.Context(), id))
		})

		large := bytes.Repeat([]byte{'a'}, 1024*1024)
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: "bob2",
			Attributes: map[string]string{
				"large": string(large),
				"small": "eyy",
			},
		}

		require.NoError(t, keychainStore.Save(t.Context(), id, secret))
		storeSecret, err := keychainStore.Get(t.Context(), id)
		require.NoError(t, err)
		assert.EqualValues(t, secret.Attributes, storeSecret.Metadata())
	})

	t.Run("filter populates both metadata and secret", func(t *testing.T) {
		id := store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())

		t.Cleanup(func() {
			assert.NoError(t, keychainStore.Delete(t.Context(), id))
		})
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: "bob2",
			Attributes: map[string]string{
				"game": "elden ring",
			},
		}

		require.NoError(t, keychainStore.Save(t.Context(), id, secret))
		secrets, err := keychainStore.Filter(t.Context(), store.MustParsePattern(id.String()))
		require.NoError(t, err)
		assert.Len(t, secrets, 1)
		assert.Subset(t, secrets[id].Metadata(), map[string]string{
			"game": "elden ring",
		})
		assert.IsType(t, &mocks.MockCredential{}, secrets[id], "secret from store must be of type *mocks.MockCredential")
		mockSecret := secrets[id].(*mocks.MockCredential)
		assert.Equal(t, secret.Password, mockSecret.Password)
	})

	t.Run("can use pattern only matching service name", func(t *testing.T) {
		id := store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())

		t.Cleanup(func() {
			assert.NoError(t, keychainStore.Delete(t.Context(), id))
		})
		secret := &mocks.MockCredential{
			Username: uuid.NewString(),
			Password: "bob2",
			Attributes: map[string]string{
				"color": "blue",
				"game":  "elden ring",
			},
		}
		require.NoError(t, keychainStore.Save(t.Context(), id, secret))
		secrets, err := keychainStore.Filter(t.Context(), store.MustParsePattern("*/"+serviceName+"/*"))
		require.NoError(t, err)
		assert.Len(t, secrets, 4)
		_, ok := secrets[id]
		assert.Truef(t, ok, "returned secret must match original id")
	})
}

func TestUpsert(t *testing.T) {
	var (
		serviceName  = uuid.NewString()
		serviceGroup = "com.test.testing"
	)
	ks := keychainStore[*mocks.MockCredential]{
		serviceGroup: serviceGroup,
		serviceName:  serviceName,
		factory: func(_ context.Context, _ store.ID) *mocks.MockCredential {
			return &mocks.MockCredential{}
		},
	}

	t.Run("inserts when credential does not exist", func(t *testing.T) {
		id := store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())
		t.Cleanup(func() {
			assert.NoError(t, ks.Delete(t.Context(), id))
		})

		secret := &mocks.MockCredential{
			Username: "alice",
			Password: "alice-password",
		}
		require.NoError(t, ks.Upsert(t.Context(), id, secret))

		got, err := ks.Get(t.Context(), id)
		require.NoError(t, err)
		actual := got.(*mocks.MockCredential)
		actual.Attributes = nil
		assert.Equal(t, secret.Username, actual.Username)
		assert.Equal(t, secret.Password, actual.Password)
	})

	t.Run("overwrites an existing credential", func(t *testing.T) {
		id := store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())
		t.Cleanup(func() {
			assert.NoError(t, ks.Delete(t.Context(), id))
		})

		original := &mocks.MockCredential{
			Username: "bob",
			Password: "original-password",
		}
		require.NoError(t, ks.Save(t.Context(), id, original))

		updated := &mocks.MockCredential{
			Username: "bob",
			Password: "updated-password",
		}
		require.NoError(t, ks.Upsert(t.Context(), id, updated))

		got, err := ks.Get(t.Context(), id)
		require.NoError(t, err)
		actual := got.(*mocks.MockCredential)
		actual.Attributes = nil
		assert.Equal(t, updated.Username, actual.Username)
		assert.Equal(t, updated.Password, actual.Password)
	})

	t.Run("updates an existing credential in place", func(t *testing.T) {
		id := store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())
		t.Cleanup(func() {
			assert.NoError(t, ks.Delete(t.Context(), id))
		})

		require.NoError(t, ks.Save(t.Context(), id, &mocks.MockCredential{
			Username:   "dana",
			Password:   "original-password",
			Attributes: map[string]string{"expiry": "1"},
		}))
		query := kc.NewItem()
		query.SetSecClass(kc.SecClassGenericPassword)
		query.SetService(serviceName)
		query.SetAccessGroup(serviceGroup)
		query.SetAccount(id.String())
		marker := kc.NewItem()
		marker.SetComment("set-outside-the-store")
		require.NoError(t, kc.UpdateItem(query, marker))

		before, err := getItemWithData(id.String(), &ks)
		require.NoError(t, err)
		require.Equal(t, "set-outside-the-store", before.Comment)

		updated := &mocks.MockCredential{
			Username:   "dana",
			Password:   "updated-password",
			Attributes: map[string]string{"expiry": "2"},
		}
		require.NoError(t, ks.Upsert(t.Context(), id, updated))

		after, err := getItemWithData(id.String(), &ks)
		require.NoError(t, err)
		assert.Equal(t, "set-outside-the-store", after.Comment, "the item must be updated, not deleted and re-added")
		assert.Equal(t, before.Label, after.Label)

		got, err := ks.Get(t.Context(), id)
		require.NoError(t, err)
		actual := got.(*mocks.MockCredential)
		assert.Equal(t, updated.Password, actual.Password)
		assert.Equal(t, map[string]string{"expiry": "2"}, actual.Metadata())
	})

	t.Run("inserts a secret whose Marshal returns its backing buffer", func(t *testing.T) {
		bs := keychainStore[*bufferSecret]{
			serviceGroup: serviceGroup,
			serviceName:  serviceName,
			factory: func(_ context.Context, _ store.ID) *bufferSecret {
				return &bufferSecret{}
			},
		}
		id := store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())
		t.Cleanup(func() {
			assert.NoError(t, bs.Delete(t.Context(), id))
		})

		require.NoError(t, bs.Upsert(t.Context(), id, &bufferSecret{value: []byte("review-test-value")}))

		got, err := bs.Get(t.Context(), id)
		require.NoError(t, err)
		assert.Equal(t, []byte("review-test-value"), got.(*bufferSecret).value)
	})

	t.Run("rejects an empty secret value and keeps the existing one", func(t *testing.T) {
		bs := keychainStore[*bufferSecret]{
			serviceGroup: serviceGroup,
			serviceName:  serviceName,
			factory: func(_ context.Context, _ store.ID) *bufferSecret {
				return &bufferSecret{}
			},
		}
		id := store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())
		t.Cleanup(func() {
			assert.NoError(t, bs.Delete(t.Context(), id))
		})

		require.NoError(t, bs.Save(t.Context(), id, &bufferSecret{value: []byte("review-old-value")}))
		require.ErrorIs(t, bs.Upsert(t.Context(), id, &bufferSecret{}), ErrEmptySecret)
		require.ErrorIs(t, bs.Upsert(t.Context(), id, &bufferSecret{value: []byte{}}), ErrEmptySecret)

		got, err := bs.Get(t.Context(), id)
		require.NoError(t, err)
		assert.Equal(t, []byte("review-old-value"), got.(*bufferSecret).value)
	})

	t.Run("save rejects an empty secret value", func(t *testing.T) {
		bs := keychainStore[*bufferSecret]{
			serviceGroup: serviceGroup,
			serviceName:  serviceName,
			factory: func(_ context.Context, _ store.ID) *bufferSecret {
				return &bufferSecret{}
			},
		}
		id := store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())
		t.Cleanup(func() {
			assert.NoError(t, bs.Delete(t.Context(), id))
		})

		require.ErrorIs(t, bs.Save(t.Context(), id, &bufferSecret{}), ErrEmptySecret)
		require.ErrorIs(t, bs.Save(t.Context(), id, &bufferSecret{value: []byte{}}), ErrEmptySecret)

		_, err := bs.Get(t.Context(), id)
		require.ErrorIs(t, err, store.ErrCredentialNotFound)
	})

	t.Run("save returns duplicate item error when credential already exists", func(t *testing.T) {
		id := store.MustParseID(serviceGroup + "/" + serviceName + "/" + uuid.NewString())
		t.Cleanup(func() {
			assert.NoError(t, ks.Delete(t.Context(), id))
		})

		secret := &mocks.MockCredential{
			Username: "charlie",
			Password: "charlie-password",
		}
		require.NoError(t, ks.Save(t.Context(), id, secret))

		err := ks.Save(t.Context(), id, secret)
		require.ErrorIs(t, err, ErrDuplicateItem)
	})
}

type bufferSecret struct {
	value    []byte
	metadata map[string]string
}

func (b *bufferSecret) Marshal() ([]byte, error) {
	return b.value, nil
}

func (b *bufferSecret) Unmarshal(data []byte) error {
	if len(data) == 0 {
		b.value = nil
		return nil
	}
	b.value = append([]byte(nil), data...)
	return nil
}

func (b *bufferSecret) Metadata() map[string]string {
	return b.metadata
}

func (b *bufferSecret) SetMetadata(md map[string]string) error {
	b.metadata = md
	return nil
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
