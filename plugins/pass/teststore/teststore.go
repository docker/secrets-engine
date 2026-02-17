// Copyright 2025-2026 Docker, Inc.
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
	errFilter error
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

func WithStoreFilterErr(err error) Option {
	return func(m *MockStore) {
		m.errFilter = err
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

	if m.errFilter != nil {
		return nil, m.errFilter
	}

	filtered := make(map[store.ID]store.Secret)
	for id, f := range m.store {
		if pattern.Match(id) {
			filtered[id] = f
		}
	}
	return filtered, nil
}
