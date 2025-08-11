package main

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/mysecret/service"
	"github.com/docker/secrets-engine/store"
)

type mockStoreOption func(m *mockStore)

type mockStore struct {
	lock      sync.RWMutex
	errSave   error
	errGetAll error
	errDelete error
	errGet    error
	store     map[string]store.Secret
}

func newMockStore(options ...mockStoreOption) store.Store {
	s := &mockStore{store: map[string]store.Secret{}}
	for _, option := range options {
		option(s)
	}
	return s
}

func withStoreSaveErr(err error) mockStoreOption {
	return func(m *mockStore) {
		m.errSave = err
	}
}

func withStoreGetErr(err error) mockStoreOption {
	return func(m *mockStore) {
		m.errGet = err
	}
}

func withStoreGetAllErr(err error) mockStoreOption {
	return func(m *mockStore) {
		m.errGetAll = err
	}
}

func withStoreDeleteErr(err error) mockStoreOption {
	return func(m *mockStore) {
		m.errDelete = err
	}
}

func withStore(store map[string]store.Secret) mockStoreOption {
	return func(m *mockStore) {
		m.store = store
	}
}

func (m *mockStore) Delete(_ context.Context, id store.ID) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.errDelete != nil {
		return m.errDelete
	}

	delete(m.store, id.String())
	return nil
}

func (m *mockStore) Get(_ context.Context, id store.ID) (store.Secret, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	if m.errGet != nil {
		return nil, m.errGet
	}

	secret, exists := m.store[id.String()]
	if !exists {
		return nil, store.ErrCredentialNotFound
	}
	return secret, nil
}

func (m *mockStore) GetAllMetadata(_ context.Context) (map[string]store.Secret, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if m.errGetAll != nil {
		return nil, m.errGetAll
	}
	return maps.Clone(m.store), nil
}

func (m *mockStore) Save(_ context.Context, id store.ID, secret store.Secret) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.errSave != nil {
		return m.errSave
	}

	m.store[id.String()] = secret
	return nil
}

func (m *mockStore) Filter(_ context.Context, pattern store.Pattern) (map[string]store.Secret, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

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

var _ store.Store = &mockStore{}

func Test_rootCommand(t *testing.T) {
	t.Parallel()
	t.Run("set secret from CLI", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			mock := newMockStore()
			out, err := executeCommand(rootCommand(t.Context(), mock), "set", "foo=bar=bar=bar")
			assert.NoError(t, err)
			assert.Empty(t, out)
			s, err := mock.Get(t.Context(), secrets.MustParseID("foo"))
			require.NoError(t, err)
			impl, ok := s.(*service.MyValue)
			require.True(t, ok)
			assert.Equal(t, "bar=bar=bar", string(impl.Value))
		})
		t.Run("store error", func(t *testing.T) {
			errSave := errors.New("save error")
			mock := newMockStore(withStoreSaveErr(errSave))
			out, err := executeCommand(rootCommand(t.Context(), mock), "set", "foo=bar")
			assert.ErrorIs(t, errSave, err)
			assert.Equal(t, "Error: "+errSave.Error()+"\n", out)
		})
		t.Run("invalid id", func(t *testing.T) {
			errSave := errors.New("save error")
			mock := newMockStore(withStoreSaveErr(errSave))
			out, err := executeCommand(rootCommand(t.Context(), mock), "set", "/foo=bar")
			errInvalidID := secrets.ErrInvalidID{ID: "/foo"}
			assert.ErrorIs(t, err, errInvalidID)
			assert.Equal(t, "Error: "+errInvalidID.Error()+"\n", out)
		})
	})
	t.Run("list", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			mock := newMockStore(withStore(map[string]store.Secret{
				"foo": &service.MyValue{Value: []byte("bar")},
				"baz": &service.MyValue{Value: []byte("0")},
			}))
			out, err := executeCommand(rootCommand(t.Context(), mock), "list")
			assert.NoError(t, err)
			assert.Equal(t, "baz\nfoo\n", out)
		})
		t.Run("store error", func(t *testing.T) {
			errGetAll := errors.New("get error")
			mock := newMockStore(withStoreGetAllErr(errGetAll))
			out, err := executeCommand(rootCommand(t.Context(), mock), "list")
			assert.ErrorIs(t, errGetAll, err)
			assert.Equal(t, "Error: "+errGetAll.Error()+"\n", out)
		})
	})
	t.Run("rm", func(t *testing.T) {
		t.Run("ok (two secrets)", func(t *testing.T) {
			mock := newMockStore(withStore(map[string]store.Secret{
				"foo": &service.MyValue{Value: []byte("bar")},
				"baz": &service.MyValue{Value: []byte("0")},
			}))
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm", "foo", "baz")
			assert.NoError(t, err)
			assert.Equal(t, "RM: baz\nRM: foo\n", out)
			l, err := mock.GetAllMetadata(t.Context())
			require.NoError(t, err)
			assert.Empty(t, l)
		})
		t.Run("--all", func(t *testing.T) {
			mock := newMockStore(withStore(map[string]store.Secret{
				"foo": &service.MyValue{Value: []byte("bar")},
				"baz": &service.MyValue{Value: []byte("0")},
			}))
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm", "--all")
			assert.NoError(t, err)
			assert.Equal(t, "RM: baz\nRM: foo\n", out)
			l, err := mock.GetAllMetadata(t.Context())
			require.NoError(t, err)
			assert.Empty(t, l)
		})
		t.Run("store error", func(t *testing.T) {
			errRemove := errors.New("remove error")
			mock := newMockStore(withStoreDeleteErr(errRemove))
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm", "foo")
			assert.ErrorIs(t, err, errRemove)
			assert.Equal(t, "ERR: foo: remove error\nError: "+errRemove.Error()+"\n", out)
		})
		t.Run("invalid id", func(t *testing.T) {
			mock := newMockStore()
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm", "/foo")
			errInvalidID := secrets.ErrInvalidID{ID: "/foo"}
			assert.ErrorIs(t, err, errInvalidID)
			assert.Equal(t, "ERR: /foo: invalid ID\nError: "+errInvalidID.Error()+"\n", out)
		})
		t.Run("cannot mix --all with explicit list", func(t *testing.T) {
			mock := newMockStore()
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm", "--all", "foo")
			assert.ErrorContains(t, err, "either provide a secret name or use --all to remove all secrets")
			assert.Equal(t, "Error: either provide a secret name or use --all to remove all secrets\n", out)
		})
		t.Run("no args or --all", func(t *testing.T) {
			mock := newMockStore()
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm")
			assert.ErrorContains(t, err, "either provide a secret name or use --all to remove all secrets")
			assert.Equal(t, "Error: either provide a secret name or use --all to remove all secrets\n", out)
		})
	})
	t.Run("get", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			mock := newMockStore(withStore(map[string]store.Secret{
				"foo": &service.MyValue{Value: []byte("bar")},
			}))
			out, err := executeCommand(rootCommand(t.Context(), mock), "get", "foo")
			assert.NoError(t, err)
			assert.Equal(t, "ID: foo\nValue: bar\n", out)
		})
		t.Run("store error", func(t *testing.T) {
			errGet := errors.New("get error")
			mock := newMockStore(withStoreGetErr(errGet))
			out, err := executeCommand(rootCommand(t.Context(), mock), "get", "foo")
			assert.ErrorIs(t, err, errGet)
			assert.Equal(t, "Error: "+errGet.Error()+"\n", out)
		})
	})
}

func executeCommand(root *cobra.Command, args ...string) (output string, err error) {
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)

	err = root.Execute()

	return buf.String(), err
}
