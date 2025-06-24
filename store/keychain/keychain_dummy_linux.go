package keychain

import (
	"context"

	"github.com/docker/secrets-engine/store"
)

var _ store.Store = &keychainStore[store.Secret]{}

// Erase implements secrets.Store.
func (k *keychainStore[T]) Delete(ctx context.Context, id store.ID) error {
	panic("unimplemented")
}

// Get implements secrets.Store.
func (k *keychainStore[T]) Get(ctx context.Context, id store.ID) (store.Secret, error) {
	panic("unimplemented")
}

// GetAll implements secrets.Store.
func (k *keychainStore[T]) GetAll(ctx context.Context) (map[store.ID]store.Secret, error) {
	panic("unimplemented")
}

// Store implements secrets.Store.
func (k *keychainStore[T]) Save(ctx context.Context, id store.ID, secret store.Secret) error {
	panic("unimplemented")
}
