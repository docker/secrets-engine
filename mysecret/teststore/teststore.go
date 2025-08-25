package teststore

import (
	"context"
	"maps"
	"sync"

	"github.com/docker/secrets-engine/store"
)

type Option func(m *MockStore)

var _ store.Store = &MockStore{}

type MockStore struct {
	lock      sync.RWMutex
	errSave   error
	errGetAll error
	errDelete error
	errGet    error
	store     map[store.ID]store.Secret
}

func NewMockStore(options ...Option) store.Store {
	s := &MockStore{store: map[store.ID]store.Secret{}}
	for _, option := range options {
		option(s)
	}
	return s
}

func WithStoreSaveErr(err error) Option {
	return func(m *MockStore) {
		m.errSave = err
	}
}

func WithStoreGetErr(err error) Option {
	return func(m *MockStore) {
		m.errGet = err
	}
}

func WithStoreGetAllErr(err error) Option {
	return func(m *MockStore) {
		m.errGetAll = err
	}
}

func WithStoreDeleteErr(err error) Option {
	return func(m *MockStore) {
		m.errDelete = err
	}
}

func WithStore(store map[store.ID]store.Secret) Option {
	return func(m *MockStore) {
		m.store = store
	}
}

func (m *MockStore) Delete(_ context.Context, id store.ID) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.errDelete != nil {
		return m.errDelete
	}

	delete(m.store, id)
	return nil
}

func (m *MockStore) Get(_ context.Context, id store.ID) (store.Secret, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	if m.errGet != nil {
		return nil, m.errGet
	}

	secret, exists := m.store[id]
	if !exists {
		return nil, store.ErrCredentialNotFound
	}
	return secret, nil
}

func (m *MockStore) GetAllMetadata(_ context.Context) (map[store.ID]store.Secret, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if m.errGetAll != nil {
		return nil, m.errGetAll
	}
	return maps.Clone(m.store), nil
}

func (m *MockStore) Save(_ context.Context, id store.ID, secret store.Secret) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.errSave != nil {
		return m.errSave
	}

	m.store[id] = secret
	return nil
}

func (m *MockStore) Filter(_ context.Context, pattern store.Pattern) (map[store.ID]store.Secret, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	filtered := make(map[store.ID]store.Secret)
	for id, f := range m.store {
		if pattern.Match(id) {
			filtered[id] = f
		}
	}
	return filtered, nil
}
