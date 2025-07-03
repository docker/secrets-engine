package adaptation

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/pkg/api"
	"github.com/docker/secrets-engine/pkg/secrets"
	p "github.com/docker/secrets-engine/plugin"
)

const (
	mockSecretValue        = "mockSecretValue"
	mockSecretID           = secrets.ID("mockSecretID")
	mockRuntimeTestTimeout = 10 * time.Second
)

type mockedPlugin struct {
	pattern      string
	id           secrets.ID
	configureErr error
}

type MockedPluginOption func(*mockedPlugin)

func newMockedPlugin(options ...MockedPluginOption) *mockedPlugin {
	m := &mockedPlugin{
		pattern: "*",
		id:      mockSecretID,
	}
	for _, opt := range options {
		opt(m)
	}
	return m
}

func WithPattern(pattern string) MockedPluginOption {
	return func(mp *mockedPlugin) {
		mp.pattern = pattern
	}
}

func WithID(id secrets.ID) MockedPluginOption {
	return func(mp *mockedPlugin) {
		mp.id = id
	}
}

func (m mockedPlugin) GetSecret(context.Context, secrets.Request) (secrets.Envelope, error) {
	return secrets.Envelope{ID: m.id, Value: []byte(mockSecretValue)}, nil
}

func (m mockedPlugin) Config() p.Config {
	return p.Config{
		Version: "v1",
		Pattern: m.pattern,
	}
}

func (m mockedPlugin) Configure(context.Context, p.RuntimeConfig) error {
	return m.configureErr
}

func (m mockedPlugin) Shutdown(context.Context) {
}

func Test_newExternalPlugin(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T, listener net.Listener, conn net.Conn)
	}{
		{
			name: "create external plugin",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := &mockExternalRuntime{l: l, done: make(chan struct{})}
				go m.run()

				s, err := p.New(newMockedPlugin(), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				runErr, cancel := runAsyncWithTimeout(t.Context(), s.Run)
				t.Cleanup(cancel)

				runtime, err := m.getRuntime()
				assert.NoError(t, err)
				e, err := runtime.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
				assert.NoError(t, err)
				assert.Equal(t, mockSecretValue, string(e.Value))
				assert.NoError(t, runtime.close())

				err = <-runErr
				assert.NoError(t, err)
			},
		},
		{
			name: "plugin returns error on GetSecret",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := &mockExternalRuntime{l: l, done: make(chan struct{})}
				go m.run()

				s, err := p.New(newMockedPlugin(WithID("rewrite-id")), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				runErr, cancel := runAsyncWithTimeout(t.Context(), s.Run)
				t.Cleanup(cancel)

				runtime, err := m.getRuntime()
				assert.NoError(t, err)
				_, err = runtime.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
				assert.ErrorContains(t, err, "id mismatch")
				assert.NoError(t, runtime.close())

				err = <-runErr
				assert.NoError(t, err)
			},
		},
		{
			name: "cancelling plugin.run() shuts down the runtime",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := &mockExternalRuntime{l: l, done: make(chan struct{})}
				go m.run()

				s, err := p.New(newMockedPlugin(), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})
				go func() {
					assert.NoError(t, s.Run(ctx))
					close(done)
				}()

				runtime, err := m.getRuntime()
				assert.NoError(t, err)
				e, err := runtime.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
				assert.NoError(t, err)
				assert.Equal(t, mockSecretValue, string(e.Value))

				cancel()
				<-done
				assert.NoError(t, runtime.close())
			},
		},
		{
			name: "plugins with invalid patterns are rejected",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				doneRuntime := make(chan struct{})
				go func() {
					conn, err := l.Accept()
					require.NoError(t, err)

					_, err = newExternalPlugin(conn, setupValidator{
						out:           pluginCfgOut{engineName: "test-engine", engineVersion: "1.0.0", requestTimeout: 30 * time.Second},
						acceptPattern: func(secrets.Pattern) error { return nil },
					})
					assert.ErrorContains(t, err, "invalid pattern")
					close(doneRuntime)
				}()

				s, err := p.New(newMockedPlugin(WithPattern("a*a")), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				assert.ErrorContains(t, s.Run(t.Context()), "invalid pattern")
				<-doneRuntime
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("XDG_RUNTIME_DIR", os.TempDir())
			socketPath := api.DefaultSocketPath()
			os.Remove(socketPath)
			require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0755))
			l, err := net.ListenUnix("unix", &net.UnixAddr{
				Name: socketPath,
				Net:  "unix",
			})
			require.NoError(t, err)
			conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
			require.NoError(t, err)
			tt.test(t, l, conn)
			conn.Close()
			l.Close()
		})
	}
}

func runAsyncWithTimeout(ctx context.Context, run func(ctx context.Context) error) (chan error, context.CancelFunc) {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, mockRuntimeTestTimeout)
	runErr := make(chan error)
	go func() {
		runErr <- run(ctxWithTimeout)
	}()
	return runErr, cancel
}

type mockExternalRuntime struct {
	l    net.Listener
	p    *runtime
	err  error
	done chan struct{}
}

func (m *mockExternalRuntime) run() {
	defer close(m.done)
	conn, err := m.l.Accept()
	if err != nil {
		m.err = err
		return
	}
	p, err := newExternalPlugin(conn, setupValidator{
		out:           pluginCfgOut{engineName: "test-engine", engineVersion: "1.0.0", requestTimeout: 30 * time.Second},
		acceptPattern: func(secrets.Pattern) error { return nil },
	})
	if err != nil {
		m.err = err
		return
	}
	m.p = p
}

func (m *mockExternalRuntime) getRuntime() (*runtime, error) {
	select {
	case <-m.done:
		return m.p, m.err
	case <-time.After(mockRuntimeTestTimeout):
		m.l.Close() // abort runtime
		return nil, errors.New("timeout")
	}
}
