package keychain

import (
	"context"

	"github.com/docker/secrets-engine/pkg/secrets"
)

var _ Store = &keychainStore[Secret]{}

// Erase implements secrets.Store.
func (k *keychainStore[T]) Erase(ctx context.Context, id secrets.ID) error {
	panic("unimplemented")
}

// Get implements secrets.Store.
func (k *keychainStore[T]) Get(ctx context.Context, id secrets.ID) (secrets.Secret, error) {
	panic("unimplemented")
}

// GetAll implements secrets.Store.
func (k *keychainStore[T]) GetAll(ctx context.Context) (map[secrets.ID]secrets.Secret, error) {
	panic("unimplemented")
}

// Store implements secrets.Store.
func (k *keychainStore[T]) Store(ctx context.Context, id secrets.ID, secret secrets.Secret) error {
	panic("unimplemented")
}
