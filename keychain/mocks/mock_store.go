package mocks

import (
	"context"
	"maps"
	"sync"

	"github.com/docker/secrets-engine/keychain"
)

type MockStore struct {
	lock  sync.RWMutex
	store map[keychain.ID]keychain.Secret
}

func (m *MockStore) init() {
	if m.store == nil {
		m.store = make(map[keychain.ID]keychain.Secret)
	}
}

// Erase implements Store.
func (m *MockStore) Erase(_ context.Context, id keychain.ID) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.init()

	delete(m.store, id)
	return nil
}

// Get implements Store.
func (m *MockStore) Get(_ context.Context, id keychain.ID) (keychain.Secret, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	m.init()

	secret, exists := m.store[id]
	if !exists {
		return nil, keychain.ErrCredentialNotFound
	}
	return secret, nil
}

// GetAll implements Store.
func (m *MockStore) GetAll(_ context.Context) (map[keychain.ID]keychain.Secret, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	m.init()

	// Return a copy of the store to avoid concurrent map read/write issues.
	return maps.Clone(m.store), nil
}

// Store implements Store.
func (m *MockStore) Store(_ context.Context, id keychain.ID, secret keychain.Secret) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.init()

	m.store[id] = secret
	return nil
}

var _ keychain.Store = &MockStore{}
