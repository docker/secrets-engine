package mocks

import (
	"context"
	"maps"
	"sync"

	"github.com/docker/secrets-engine/store"
)

type MockStore struct {
	lock  sync.RWMutex
	store map[string]store.Secret
}

func (m *MockStore) init() {
	if m.store == nil {
		m.store = make(map[string]store.Secret)
	}
}

// Delete implements Store.
func (m *MockStore) Delete(_ context.Context, id store.ID) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.init()

	delete(m.store, id.String())
	return nil
}

// Get implements Store.
func (m *MockStore) Get(_ context.Context, id store.ID) (store.Secret, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	m.init()

	secret, exists := m.store[id.String()]
	if !exists {
		return nil, store.ErrCredentialNotFound
	}
	return secret, nil
}

// GetAll implements Store.
func (m *MockStore) GetAllMetadata(_ context.Context) (map[string]store.Secret, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	m.init()

	// Return a copy of the store to avoid concurrent map read/write issues.
	return maps.Clone(m.store), nil
}

// Save implements Store.
func (m *MockStore) Save(_ context.Context, id store.ID, secret store.Secret) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.init()

	m.store[id.String()] = secret
	return nil
}

var _ store.Store = &MockStore{}
