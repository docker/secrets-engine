package keychain

import (
	"errors"

	"github.com/docker/secrets-engine/store"
)

var ErrCollectionPathInvalid = errors.New("keychain collection path is invalid")

const (
	// the docker label is the default prefix on all keys stored by the keychain
	// e.g. io.docker.Secrets:id(realm/app/username)
	dockerSecretsLabel = "io.docker.Secrets"
)

type keychainStore[T store.Secret] struct {
	keyPrefix string
	factory   func() T
}

var _ store.Store = &keychainStore[store.Secret]{}

type Factory[T store.Secret] func() T

type Options[T store.Secret] func(*keychainStore[T]) error

func WithKeyPrefix[T store.Secret](prefix string) Options[T] {
	return func(ks *keychainStore[T]) error {
		if prefix == "" {
			return errors.New("the prefix cannot be empty")
		}
		ks.keyPrefix = prefix
		return nil
	}
}

// New creates a new keychain store
//
// factory is a function used to instantiate new secrets of type T.
func New[T store.Secret](factory Factory[T], opts ...Options[T]) (store.Store, error) {
	k := &keychainStore[T]{
		factory:   factory,
		keyPrefix: dockerSecretsLabel,
	}
	for _, o := range opts {
		if err := o(k); err != nil {
			return nil, err
		}
	}
	return k, nil
}
