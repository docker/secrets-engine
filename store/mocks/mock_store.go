package mocks

import (
	"context"
	"maps"
	"sync"

	"github.com/docker/secrets-engine/store"
)

type MockStore struct {
	lock  sync.RWMutex
	store map[store.ID]store.Secret
}

func (m *MockStore) init() {
	if m.store == nil {
		m.store = make(map[store.ID]store.Secret)
	}
}

// Delete implements Store.
func (m *MockStore) Delete(_ context.Context, id store.ID) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.init()

	delete(m.store, id)
	return nil
}

// Get implements Store.
func (m *MockStore) Get(_ context.Context, id store.ID) (store.Secret, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	m.init()

	secret, exists := m.store[id]
	if !exists {
		return nil, store.ErrCredentialNotFound
	}
	return secret, nil
}

// GetAll implements Store.
func (m *MockStore) GetAllMetadata(_ context.Context) (map[store.ID]store.Secret, error) {
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

	m.store[id] = secret
	return nil
}

var _ store.Store = &MockStore{}
