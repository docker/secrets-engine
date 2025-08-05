package mocks

import (
	"context"
	"maps"
	"sync"

	"github.com/docker/secrets-engine/internal/secrets"
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

func (m *MockStore) Delete(_ context.Context, id store.ID) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.init()

	delete(m.store, id.String())
	return nil
}

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

func (m *MockStore) GetAllMetadata(_ context.Context) (map[string]store.Secret, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	m.init()
	return maps.Clone(m.store), nil
}

func (m *MockStore) Save(_ context.Context, id store.ID, secret store.Secret) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.init()

	m.store[id.String()] = secret
	return nil
}

func (m *MockStore) Filter(_ context.Context, pattern store.Pattern) (map[string]store.Secret, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.init()

	filtered := make(map[string]store.Secret)
	for id, f := range m.store {
		p, err := secrets.ParseID(id)
		if err != nil {
			continue
		}
		if pattern.Match(p) {
			filtered[p.String()] = f
		}
	}
	return filtered, nil
}

var _ store.Store = &MockStore{}
