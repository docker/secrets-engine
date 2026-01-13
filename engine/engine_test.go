package engine

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/engine/internal/mocks"
	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/engine/internal/registry"
	"github.com/docker/secrets-engine/engine/internal/testdummy"
	et "github.com/docker/secrets-engine/engine/internal/testhelper"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

type mockSlowRuntime struct {
	name api.Name
}

func (m *mockSlowRuntime) Name() api.Name {
	return m.name
}

func (m *mockSlowRuntime) Version() api.Version {
	return mockValidVersion
}

func (m *mockSlowRuntime) Pattern() secrets.Pattern {
	return mockPattern
}

func (m *mockSlowRuntime) Closed() <-chan struct{} {
	return nil
}

func (m *mockSlowRuntime) GetSecrets(context.Context, secrets.Pattern) ([]secrets.Envelope, error) {
	return []secrets.Envelope{}, nil
}

func (m *mockSlowRuntime) Close() error {
	time.Sleep(10 * time.Millisecond)
	return fmt.Errorf("%s closed", m.name)
}

func newMockIterator(runtimes []plugin.Runtime) iter.Seq[plugin.Runtime] {
	return func(yield func(plugin.Runtime) bool) {
		for i := 0; i < len(runtimes); i++ {
			if !yield(runtimes[i]) {
				return
			}
		}
	}
}

// Unfortunately, there's no way to test this reliably using channels.
// We instead have a tiny sleep per mockRuntime.Close() with a larger global timeout in case the parallelStop function locks.
func Test_parallelStop(t *testing.T) {
	var runtimes []plugin.Runtime
	for i := range 10000 {
		runtimes = append(runtimes, &mockSlowRuntime{name: api.MustNewName(fmt.Sprintf("r%d", i))})
	}
	stopErr := make(chan error)
	go func() {
		stopErr <- parallelStop(newMockIterator(runtimes))
	}()
	select {
	case err := <-stopErr:
		assert.ErrorContains(t, err, "r24")
		assert.ErrorContains(t, err, "r32")
	case <-time.After(time.Second):
		t.Fatal("timeout: parallel stop should not exceed 1s")
	}
}

type mockRegistry struct {
	addCalled    []plugin.Runtime
	removed      chan struct{}
	removeCalled int
	err          error
}

func (m *mockRegistry) Iterator() iter.Seq[plugin.Runtime] {
	return func(func(plugin.Runtime) bool) {}
}

func (m *mockRegistry) Register(plugin plugin.Runtime) (registry.RemoveFunc, error) {
	m.addCalled = append(m.addCalled, plugin)
	return func() {
		m.removeCalled++
		if m.removed != nil {
			close(m.removed)
		}
	}, m.err
}

func Test_Register(t *testing.T) {
	t.Parallel()
	t.Run("nothing gets registered when launch returns an error", func(t *testing.T) {
		reg := &mockRegistry{}
		launchErr := errors.New("launch error")
		l := func() (plugin.Runtime, error) {
			return nil, launchErr
		}
		errCh, err := register(testhelper.TestLoggerCtx(t), reg, l)
		assert.ErrorIs(t, err, launchErr)
		assert.Nil(t, errCh)
	})
	t.Run("when Register() returns an error, Close() is called", func(t *testing.T) {
		errRegister := errors.New("register error")
		reg := &mockRegistry{err: errRegister}
		r := &mocks.MockRuntime{}
		l := func() (plugin.Runtime, error) {
			return r, nil
		}
		errCh, err := register(testhelper.TestLoggerCtx(t), reg, l)
		assert.ErrorIs(t, err, errRegister)
		assert.Nil(t, errCh)
		assert.Equal(t, 1, r.CloseCalled)
	})
	t.Run("runtime gets unregistered when channel is closed", func(t *testing.T) {
		reg := &mockRegistry{removed: make(chan struct{})}
		r := &mocks.MockRuntime{RuntimeClosed: make(chan struct{})}
		l := func() (plugin.Runtime, error) {
			return r, nil
		}
		errCh, err := register(testhelper.TestLoggerCtx(t), reg, l)
		assert.NoError(t, err)
		assert.Equal(t, 0, reg.removeCalled)
		close(r.RuntimeClosed)
		<-reg.removed
		assert.Equal(t, 1, reg.removeCalled)
		assert.NoError(t, testhelper.WaitForErrorWithTimeout(errCh))
	})
	t.Run("runtime gets unregistered when runtime closed channel is nil", func(t *testing.T) {
		reg := &mockRegistry{removed: make(chan struct{})}
		r := &mocks.MockRuntime{}
		l := func() (plugin.Runtime, error) {
			return r, nil
		}
		errCh, err := register(testhelper.TestLoggerCtx(t), reg, l)
		assert.NoError(t, err)
		<-reg.removed
		assert.Equal(t, 1, reg.removeCalled)
		assert.NoError(t, testhelper.WaitForErrorWithTimeout(errCh))
	})
}

func Test_discoverPlugins(t *testing.T) {
	t.Parallel()
	t.Run("only discover plugins but ignore everything else", func(t *testing.T) {
		dir := t.TempDir()
		assert.NoError(t, os.MkdirAll(filepath.Join(dir, "could-be-a-plugin"), 0o755))
		assert.NoError(t, os.WriteFile(filepath.Join(dir, "text-file"), []byte(""), 0o644))
		assert.NoError(t, createFakeExecutable(filepath.Join(dir, "binary-file")))
		assert.NoError(t, createFakeExecutable(filepath.Join(dir, "my-plugin")))
		cfg := et.NewEngineConfig(t, et.WithPluginPath(dir))
		plugins, err := scanPluginDir(cfg)

		assert.NoError(t, err)
		assert.Len(t, plugins, 2)
		assert.Contains(t, plugins, "binary-file"+suffix)
		assert.Contains(t, plugins, "my-plugin"+suffix)
	})
	t.Run("empty list but no error if directory does not exist", func(t *testing.T) {
		dir := t.TempDir()
		cfg := et.NewEngineConfig(t,
			et.WithPluginPath(filepath.Join(dir, "does-not-exist")),
		)

		plugins, err := scanPluginDir(cfg)
		assert.NoError(t, err)
		assert.Empty(t, plugins)
	})
	t.Run("empty dir string", func(t *testing.T) {
		cfg := et.NewEngineConfig(t)
		plugins, err := scanPluginDir(cfg)
		assert.NoError(t, err)
		assert.Empty(t, plugins)
	})
}

func newListener(t *testing.T, socketPath string) net.Listener {
	t.Helper()
	listener, err := createListener(socketPath)
	require.NoError(t, err)
	return listener
}

func Test_newEngine(t *testing.T) {
	t.Parallel()
	t.Run("can retrieve secret from external plugin (no crashes)", func(t *testing.T) {
		plugins := []testdummy.PluginBehaviour{{Value: "foo"}}
		dir := testdummy.CreateDummyPlugins(t, testdummy.Plugins{Plugins: plugins})
		socketPath := testhelper.RandomShortSocketName()
		cfg := et.NewEngineConfig(t,
			et.WithName("test-engine"),
			et.WithVersion("v6"),
			et.WithPluginPath(dir),
			et.WithPluginLaunchMaxRetries(1),
			et.WithListener(newListener(t, socketPath)),
		)

		e, err := newEngine(testhelper.TestLoggerCtx(t), cfg)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, e.Close()) })
		c, err := client.New(client.WithSocketPath(socketPath))
		require.NoError(t, err)
		foo, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("foo"))
		require.NoError(t, err)
		require.NotEmpty(t, foo)
		assert.Equal(t, "foo", foo[0].ID.String())
		assert.Equal(t, "foo-value", string(foo[0].Value))
	})
	t.Run("external plugin crashes on second get secret request (no recovery -> plugins get removed)", func(t *testing.T) {
		plugins := []testdummy.PluginBehaviour{{Value: "bar"}}
		dir := testdummy.CreateDummyPlugins(t, testdummy.Plugins{Plugins: plugins})
		socketPath := testhelper.RandomShortSocketName()
		cfg := et.NewEngineConfig(t,
			et.WithName("test-engine"),
			et.WithVersion("v8"),
			et.WithPluginPath(dir),
			et.WithListener(newListener(t, socketPath)),
			et.WithPluginLaunchMaxRetries(1),
		)
		e, err := newEngine(testhelper.TestLoggerCtx(t), cfg)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, e.Close()) })
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			assert.ElementsMatch(collect, e.Plugins(), []string{"plugin-bar"})
		}, 2*time.Second, 100*time.Millisecond)
		c, err := client.New(client.WithSocketPath(socketPath))
		require.NoError(t, err)
		bar, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("bar"))
		require.NoError(t, err)
		require.NotEmpty(t, bar)
		assert.Equal(t, "bar", bar[0].ID.String())
		assert.Equal(t, "bar-value", string(bar[0].Value))
		killAllPlugins(t, getRegistry(t, e))
		_, err = c.GetSecrets(t.Context(), secrets.MustParsePattern("bar"))
		assert.ErrorIs(t, err, secrets.ErrNotFound)
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			assert.Empty(collect, e.Plugins())
		}, 4*time.Second, 100*time.Millisecond)
		_, err = c.GetSecrets(t.Context(), secrets.MustParsePattern("bar"))
		assert.ErrorIs(t, err, secrets.ErrNotFound)
	})
	t.Run("internal plugin crashes on second get secret request (no recovery -> plugins get removed)", func(t *testing.T) {
		socketPath := testhelper.RandomShortSocketName()
		internalPluginRunExitCh := make(chan struct{})
		validConfig, err := plugin.NewValidatedConfig(plugin.Unvalidated{
			Name:    "my-builtin",
			Version: mockValidVersion.String(),
			Pattern: mockPatternAny.String(),
		})
		require.NoError(t, err)

		cfg := et.NewEngineConfig(t,
			et.WithName("test-engine"),
			et.WithVersion("v9"),
			et.WithPluginsDisabled(true),
			et.WithListener(newListener(t, socketPath)),
			et.WithPluginLaunchMaxRetries(1),
			et.WithPlugins(map[plugin.Metadata]plugin.Plugin{
				validConfig: &mocks.MockInternalPlugin{
					RunExitCh: internalPluginRunExitCh,
					Secrets:   map[secrets.ID]string{secrets.MustParseID("my-secret"): "some-value"},
				},
			}),
		)
		e, err := newEngine(testhelper.TestLoggerCtx(t), cfg)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, e.Close()) })
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			assert.ElementsMatch(collect, e.Plugins(), []string{"my-builtin"})
		}, 2*time.Second, 100*time.Millisecond)
		c, err := client.New(client.WithSocketPath(socketPath))
		require.NoError(t, err)
		mySecret, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("my-secret"))
		require.NoError(t, err)
		require.NotEmpty(t, mySecret)
		assert.Equal(t, "my-secret", mySecret[0].ID.String())
		assert.Equal(t, "some-value", string(mySecret[0].Value))
		close(internalPluginRunExitCh)
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			assert.Empty(collect, e.Plugins())
		}, 2*time.Second, 100*time.Millisecond)
		_, err = c.GetSecrets(t.Context(), secrets.MustParsePattern("my-secret"))
		assert.ErrorIs(t, err, secrets.ErrNotFound)
	})
	t.Run("external plugin crashes and gets recovered", func(t *testing.T) {
		plugins := []testdummy.PluginBehaviour{{Value: "bar"}}
		dir := testdummy.CreateDummyPlugins(t, testdummy.Plugins{Plugins: plugins})
		socketPath := testhelper.RandomShortSocketName()
		cfg := et.NewEngineConfig(t,
			et.WithName("test-engine"),
			et.WithVersion("v99"),
			et.WithPluginPath(dir),
			et.WithListener(newListener(t, socketPath)),
		)
		e, err := newEngine(testhelper.TestLoggerCtx(t), cfg)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, e.Close()) })
		c, err := client.New(client.WithSocketPath(socketPath))
		require.NoError(t, err)
		_, err = c.GetSecrets(t.Context(), secrets.MustParsePattern("bar"))
		require.NoError(t, err)
		killAllPlugins(t, getRegistry(t, e))
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			bar, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("bar"))
			require.NoError(collect, err)
			require.NotEmpty(collect, bar)
			assert.Equal(collect, "bar", bar[0].ID.String())
			assert.Equal(collect, "bar-value", string(bar[0].Value))
			// TODO: Make this test more reliable
		}, 30*time.Second, 100*time.Millisecond)
	})
	t.Run("internal plugin crashes (recovery)", func(t *testing.T) {
		socketPath := testhelper.RandomShortSocketName()
		blockRunCh := make(chan struct{}, 1)
		blockRunCh <- struct{}{}
		runExitCh := make(chan struct{}, 1)
		validConfig, err := plugin.NewValidatedConfig(plugin.Unvalidated{
			Name:    "my-builtin",
			Version: mockValidVersion.String(),
			Pattern: mockPatternAny.String(),
		})
		require.NoError(t, err)

		cfg := et.NewEngineConfig(t,
			et.WithName("test-engine"),
			et.WithVersion("v1"),
			et.WithPluginsDisabled(true),
			et.WithListener(newListener(t, socketPath)),
			et.WithPlugins(map[plugin.Metadata]plugin.Plugin{
				validConfig: &mocks.MockInternalPlugin{
					BlockRunForever: blockRunCh,
					RunExitCh:       runExitCh,
					Secrets:         map[secrets.ID]string{secrets.MustParseID("my-secret"): "some-value"},
				},
			}),
		)

		e, err := newEngine(testhelper.TestLoggerCtx(t), cfg)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, e.Close()) })
		c, err := client.New(client.WithSocketPath(socketPath))
		require.NoError(t, err)
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			assert.ElementsMatch(collect, e.Plugins(), []string{"my-builtin"})
		}, 2*time.Second, 100*time.Millisecond)

		runExitCh <- struct{}{}
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			assert.Empty(collect, e.Plugins())
		}, 2*time.Second, 100*time.Millisecond)

		select {
		case blockRunCh <- struct{}{}:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for block run")
		}
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			assert.ElementsMatch(collect, e.Plugins(), []string{"my-builtin"})
		}, 5*time.Second, 100*time.Millisecond) // Timeout needs to be larger than the initial retry interval
		mySecret, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("my-secret"))
		require.NoError(t, err)
		require.NotEmpty(t, mySecret)
		assert.Equal(t, "my-secret", mySecret[0].ID.String())
		assert.Equal(t, "some-value", string(mySecret[0].Value))
	})
}

func getRegistry(t *testing.T, e engine) registry.Registry {
	t.Helper()
	impl, ok := e.(*engineImpl)
	require.True(t, ok)
	return impl.reg
}

func killAllPlugins(t *testing.T, r registry.Registry) {
	t.Helper()
	for p := range r.Iterator() {
		if ep, ok := p.(plugin.ExternalRuntime); ok {
			require.NoError(t, ep.Watcher().Kill())
		}
	}
}
