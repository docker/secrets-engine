package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/internal/secrets"
)

type mockSlowRuntime struct {
	name string
}

func (m *mockSlowRuntime) Closed() <-chan struct{} {
	return nil
}

func (m *mockSlowRuntime) GetSecret(context.Context, secrets.Request) (secrets.Envelope, error) {
	return secrets.Envelope{}, nil
}

func (m *mockSlowRuntime) Close() error {
	time.Sleep(10 * time.Millisecond)
	return fmt.Errorf("%s closed", m.name)
}

func (m *mockSlowRuntime) Data() pluginData {
	return pluginData{}
}

// Unfortunately, there's no way to test this reliably using channels.
// We instead have a tiny sleep per mockRuntime.Close() with a larger global timeout in case the parallelStop function locks.
func Test_parallelStop(t *testing.T) {
	var runtimes []runtime
	for i := 0; i < 10000; i++ {
		runtimes = append(runtimes, &mockSlowRuntime{name: fmt.Sprintf("r%d", i)})
	}
	stopErr := make(chan error)
	go func() {
		stopErr <- parallelStop(runtimes)
	}()
	select {
	case err := <-stopErr:
		assert.ErrorContains(t, err, "r24")
		assert.ErrorContains(t, err, "r32")
	case <-time.After(time.Second):
		t.Fatal("timeout: parallel stop should not exceed 1s")
	}
}

type mockRuntime struct {
	name        string
	closeCalled int
	closed      chan struct{}
}

func (m *mockRuntime) GetSecret(context.Context, secrets.Request) (secrets.Envelope, error) {
	return secrets.Envelope{}, nil
}

func (m *mockRuntime) Close() error {
	m.closeCalled++
	return nil
}

func (m *mockRuntime) Closed() <-chan struct{} {
	return m.closed
}

func (m *mockRuntime) Data() pluginData {
	return pluginData{name: m.name}
}

type mockRegistry struct {
	addCalled    []runtime
	removed      chan struct{}
	removeCalled int
	err          error
}

func (m *mockRegistry) Register(plugin runtime) (removeFunc, error) {
	m.addCalled = append(m.addCalled, plugin)
	return func() {
		m.removeCalled++
		if m.removed != nil {
			close(m.removed)
		}
	}, m.err
}

func (m *mockRegistry) GetAll() []runtime {
	return nil
}

func Test_Register(t *testing.T) {
	t.Run("nothing gets registered when launch returns an error", func(t *testing.T) {
		reg := &mockRegistry{}
		launchErr := errors.New("launch error")
		l := func() (runtime, error) {
			return nil, launchErr
		}
		assert.ErrorIs(t, register(reg, l), launchErr)
	})
	t.Run("when Register() returns an error, Close() is called", func(t *testing.T) {
		errRegister := errors.New("register error")
		reg := &mockRegistry{err: errRegister}
		r := &mockRuntime{}
		l := func() (runtime, error) {
			return r, nil
		}
		assert.ErrorIs(t, register(reg, l), errRegister)
		assert.Equal(t, 1, r.closeCalled)
	})
	t.Run("runtime gets unregistered when channel is closed", func(t *testing.T) {
		reg := &mockRegistry{removed: make(chan struct{})}
		r := &mockRuntime{closed: make(chan struct{})}
		l := func() (runtime, error) {
			return r, nil
		}
		assert.NoError(t, register(reg, l))
		assert.Equal(t, 0, reg.removeCalled)
		close(r.closed)
		<-reg.removed
		assert.Equal(t, 1, reg.removeCalled)
		assert.Equal(t, 0, r.closeCalled)
	})
	t.Run("runtime gets unregistered when channel is nil", func(t *testing.T) {
		reg := &mockRegistry{removed: make(chan struct{})}
		r := &mockRuntime{}
		l := func() (runtime, error) {
			return r, nil
		}
		assert.NoError(t, register(reg, l))
		<-reg.removed
		assert.Equal(t, 1, reg.removeCalled)
		assert.Equal(t, 0, r.closeCalled)
	})
}

func Test_discoverPlugins(t *testing.T) {
	t.Run("only discover plugins but ignore everything else", func(t *testing.T) {
		dir := t.TempDir()
		assert.NoError(t, os.MkdirAll(filepath.Join(dir, "could-be-a-plugin"), 0o755))
		assert.NoError(t, os.WriteFile(filepath.Join(dir, "text-file"), []byte(""), 0o644))
		// TODO: port to windows once we run our tests on windows
		assert.NoError(t, os.WriteFile(filepath.Join(dir, "binary-file"), []byte(""), 0o755))
		assert.NoError(t, os.WriteFile(filepath.Join(dir, "my-plugin"), []byte(""), 0o755))
		plugins, err := discoverPlugins(dir)
		assert.NoError(t, err)
		assert.Len(t, plugins, 2)
		assert.Contains(t, plugins, "binary-file")
		assert.Contains(t, plugins, "my-plugin")
	})
	t.Run("empty list but no error if directory does not exist", func(t *testing.T) {
		dir := t.TempDir()
		plugins, err := discoverPlugins(filepath.Join(dir, "does-not-exist"))
		assert.NoError(t, err)
		assert.Empty(t, plugins)
	})
	t.Run("empty dir string", func(t *testing.T) {
		plugins, err := discoverPlugins("")
		assert.NoError(t, err)
		assert.Empty(t, plugins)
	})
}

func Test_startPlugins(t *testing.T) {
	okPlugin := "plugin-ok"
	dir := createDummyPlugins(t, dummyPlugins{failPlugin: true, okPlugins: []string{okPlugin}})
	reg := &manager{}
	require.NoError(t, startPlugins(config{
		name:       "test-engine",
		version:    "test-version",
		pluginPath: dir,
	}, reg))
	plugins := reg.GetAll()
	assert.Len(t, plugins, 1)
	assert.Equal(t, okPlugin, plugins[0].Data().name)
	for _, plugin := range plugins {
		assert.NoError(t, plugin.Close())
	}
	assert.Empty(t, reg.GetAll())
}

func Test_newEngine(t *testing.T) {
	okPlugins := []string{"plugin-foo"}
	dir := createDummyPlugins(t, dummyPlugins{okPlugins: okPlugins})
	socketPath := filepath.Join(t.TempDir(), "test.sock")
	cfg := config{
		name:       "test-engine",
		version:    "test-version",
		pluginPath: dir,
		socketPath: socketPath,
	}
	e, err := newEngine(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, e.Close()) })
	c, err := client.New(client.WithSocketPath(socketPath))
	require.NoError(t, err)
	foo, err := c.GetSecret(t.Context(), secrets.Request{ID: "foo"})
	assert.NoError(t, err)
	assert.Equal(t, secrets.ID("foo"), foo.ID)
	assert.Equal(t, "foo-value", string(foo.Value))
}
