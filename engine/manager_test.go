package engine

import (
	"iter"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/docker/secrets-engine/engine/internal/mocks"
	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/engine/internal/registry"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/testhelper"
)

func TestManager_Register(t *testing.T) {
	t.Parallel()
	t.Run("add and remove", func(t *testing.T) {
		m := newManager(testhelper.TestLogger(t))
		p := &mocks.MockRuntime{RuntimeName: api.MustNewName("foo")}
		rm, err := m.Register(p)
		assert.NoError(t, err)
		assert.Equal(t, []plugin.Runtime{p}, getAll(m))
		rm()
		assert.Empty(t, getAll(m))
	})
	t.Run("can register multiple plugins with different names and result of GetAll is sorted", func(t *testing.T) {
		m := newManager(testhelper.TestLogger(t))
		p1 := &mocks.MockRuntime{RuntimeName: api.MustNewName("foo")}
		_, err := m.Register(p1)
		assert.NoError(t, err)
		p2 := &mocks.MockRuntime{RuntimeName: api.MustNewName("bar")}
		rm2, err := m.Register(p2)
		assert.NoError(t, err)
		assert.Equal(t, []plugin.Runtime{p2, p1}, getAll(m))
		rm2()
		assert.Equal(t, []plugin.Runtime{p1}, getAll(m))
	})
	t.Run("cannot register another plugin with same name", func(t *testing.T) {
		m := newManager(testhelper.TestLogger(t))
		p1 := &mocks.MockRuntime{RuntimeName: api.MustNewName("bar")}
		_, err := m.Register(p1)
		assert.NoError(t, err)
		p2 := &mocks.MockRuntime{RuntimeName: api.MustNewName("bar")}
		_, err = m.Register(p2)
		assert.ErrorContains(t, err, "already exists")
	})
	t.Run("iterator", func(t *testing.T) {
		t.Run("on empty manager", func(t *testing.T) {
			m := newManager(testhelper.TestLogger(t))
			next, stop := iter.Pull(m.Iterator())
			defer stop()

			v, ok := next()
			assert.False(t, ok)
			assert.Nil(t, v)

			v, ok = next()
			assert.False(t, ok, "further next() calls do not change anything")
			assert.Nil(t, v)
		})
		t.Run("on non-empty manager", func(t *testing.T) {
			m := newManager(testhelper.TestLogger(t))
			p := &mocks.MockRuntime{RuntimeName: api.MustNewName("foo")}
			_, err := m.Register(p)
			assert.NoError(t, err)

			next, stop := iter.Pull(m.Iterator())
			defer stop()

			v, ok := next()
			assert.True(t, ok)
			assert.NotNil(t, v)

			v, ok = next()
			assert.False(t, ok)
			assert.Nil(t, v)

			v, ok = next()
			assert.False(t, ok, "further next() calls do not change anything")
			assert.Nil(t, v)
		})
		t.Run("remove before iterator position", func(t *testing.T) {
			m := newManager(testhelper.TestLogger(t))
			p1 := &mocks.MockRuntime{RuntimeName: api.MustNewName("foo")}
			rm, err := m.Register(p1)
			assert.NoError(t, err)

			next, stop := iter.Pull(m.Iterator())
			defer stop()

			rm()

			v, ok := next()
			assert.False(t, ok)
			assert.Nil(t, v)
		})
		t.Run("remove after iterator position", func(t *testing.T) {
			m := newManager(testhelper.TestLogger(t))
			p1 := &mocks.MockRuntime{RuntimeName: api.MustNewName("foo")}
			rm, err := m.Register(p1)
			assert.NoError(t, err)
			p2 := &mocks.MockRuntime{RuntimeName: api.MustNewName("bar")}
			_, err = m.Register(p2)
			assert.NoError(t, err)

			next, stop := iter.Pull(m.Iterator())
			defer stop()

			v, ok := next()
			assert.True(t, ok)
			assert.NotNil(t, v)

			rm()

			v, ok = next()
			assert.True(t, ok)
			assert.NotNil(t, v)

			v, ok = next()
			assert.False(t, ok)
			assert.Nil(t, v)
		})
		t.Run("add after iterator position", func(t *testing.T) {
			m := newManager(testhelper.TestLogger(t))
			p1 := &mocks.MockRuntime{RuntimeName: api.MustNewName("foo")}
			_, err := m.Register(p1)
			assert.NoError(t, err)

			next, stop := iter.Pull(m.Iterator())
			defer stop()

			p2 := &mocks.MockRuntime{RuntimeName: api.MustNewName("bar")}
			_, err = m.Register(p2)
			assert.NoError(t, err)

			v, ok := next()
			assert.True(t, ok)
			assert.NotNil(t, v)

			v, ok = next()
			assert.True(t, ok)
			assert.NotNil(t, v)

			v, ok = next()
			assert.False(t, ok)
			assert.Nil(t, v)
		})
		t.Run("add after iterator finished", func(t *testing.T) {
			m := newManager(testhelper.TestLogger(t))
			next, stop := iter.Pull(m.Iterator())
			defer stop()

			p := &mocks.MockRuntime{RuntimeName: api.MustNewName("foo")}
			_, err := m.Register(p)
			assert.NoError(t, err)

			v, ok := next()
			assert.False(t, ok)
			assert.Nil(t, v)
		})
	})
}

func getAll(reg registry.Registry) []plugin.Runtime {
	var results []plugin.Runtime
	for p := range reg.Iterator() {
		results = append(results, p)
	}
	return results
}
