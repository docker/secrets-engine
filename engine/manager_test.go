package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestManager_Register(t *testing.T) {
	t.Parallel()
	t.Run("add and remove", func(t *testing.T) {
		m := &manager{logger: testLogger(t)}
		p := &mockRuntime{name: "foo"}
		rm, err := m.Register(p)
		assert.NoError(t, err)
		assert.Equal(t, []runtime{p}, m.GetAll())
		rm()
		assert.Empty(t, m.GetAll())
	})
	t.Run("can register multiple plugins with different names and result of GetAll is sorted", func(t *testing.T) {
		m := &manager{logger: testLogger(t)}
		p1 := &mockRuntime{name: "foo"}
		_, err := m.Register(p1)
		assert.NoError(t, err)
		p2 := &mockRuntime{name: "bar"}
		rm2, err := m.Register(p2)
		assert.NoError(t, err)
		assert.Equal(t, []runtime{p2, p1}, m.GetAll())
		rm2()
		assert.Equal(t, []runtime{p1}, m.GetAll())
	})
	t.Run("cannot register another plugin with same name", func(t *testing.T) {
		m := &manager{logger: testLogger(t)}
		p1 := &mockRuntime{name: "bar"}
		_, err := m.Register(p1)
		assert.NoError(t, err)
		p2 := &mockRuntime{name: "bar"}
		_, err = m.Register(p2)
		assert.ErrorContains(t, err, "already exists")
	})
	t.Run("cannot register plugin without a name", func(t *testing.T) {
		m := &manager{logger: testLogger(t)}
		p := &mockRuntime{}
		_, err := m.Register(p)
		assert.ErrorContains(t, err, "no plugin name")
	})
}
