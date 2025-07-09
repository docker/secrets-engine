package engine

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/pkg/api"
	"github.com/docker/secrets-engine/pkg/secrets"
	p "github.com/docker/secrets-engine/plugin"
)

const (
	mockEngineName         = "mockEngineName"
	mockEngineVersion      = "mockEngineVersion"
	mockRuntimeTestTimeout = 10 * time.Second
)

type mockedPlugin struct {
	pattern string
	id      secrets.ID
}

type MockedPluginOption func(*mockedPlugin)

func newMockedPlugin(options ...MockedPluginOption) *mockedPlugin {
	m := &mockedPlugin{
		pattern: mockPattern,
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

func (m mockedPlugin) Shutdown(context.Context) {
}

func getTestBinaryName() string {
	if len(os.Args) == 0 {
		return ""
	}
	return filepath.Base(os.Args[0])
}

// TestMain acts as a dispatcher to run as dummy plugin or normal test.
// Inspired by: https://github.com/golang/go/blob/15d9fe43d648764d41a88c75889c84df5e580930/src/os/exec/exec_test.go#L69-L73
func TestMain(m *testing.M) {
	binaryName := getTestBinaryName()
	if strings.HasPrefix(binaryName, "plugin") {
		// This allows tests to call the test binary as plugin by creating a symlink prefixed with "plugin-" to it.
		// We then based on the suffix in dummyPluginProcessFromBinaryName() set the behavior of the plugin.
		dummyPluginProcessFromBinaryName(binaryName)
	} else if os.Getenv("RUN_AS_DUMMY_PLUGIN") != "" {
		dummyPluginProcess(nil)
	} else {
		os.Exit(m.Run())
	}
}

func Test_newPlugin(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "engine launched plugin",
			test: func(t *testing.T) {
				pattern := "foo-bar"
				version := "my-version"
				cmd, parseOutput := dummyPluginCommand(t, dummyPluginCfg{
					Config: p.Config{
						Version: version,
						Pattern: pattern,
					},
					E: []secrets.Envelope{{ID: mockSecretID, Value: []byte(mockSecretValue)}},
				})
				p, err := newLaunchedPlugin(cmd, setupValidator{
					name:          "dummy-plugin",
					out:           pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
					acceptPattern: func(secrets.Pattern) error { return nil },
				})
				assert.NoError(t, err)
				assert.Equal(t, p.Data(), pluginData{
					name:       "dummy-plugin",
					pattern:    secrets.Pattern(pattern),
					version:    version,
					pluginType: internalPlugin,
				})
				s, err := p.GetSecret(context.Background(), secrets.Request{ID: mockSecretID})
				assert.NoError(t, err)
				assert.Equal(t, mockSecretValue, string(s.Value))
				assert.NoError(t, p.Close())
				assert.NoError(t, checkClosed(p.Closed()))
				r, err := parseOutput()
				require.NoError(t, err)
				require.Equal(t, 1, len(r.GetSecret))
				assert.Equal(t, mockSecretID, r.GetSecret[0].ID)
				assert.Equal(t, 1, r.ConfigRequests)

				t.Logf("plugin binary output:\n%s", r.Log)
			},
		},
		{
			name: "plugin returns no secret but an error",
			test: func(t *testing.T) {
				errGetSecret := "you do not get my secret"
				cmd, parseOutput := dummyPluginCommand(t, dummyPluginCfg{
					Config: p.Config{
						Version: "my-version",
						Pattern: "foo-bar",
					},
					ErrGetSecret: errGetSecret,
				})
				p, err := newLaunchedPlugin(cmd, setupValidator{
					name:          "dummy-plugin",
					out:           pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
					acceptPattern: func(secrets.Pattern) error { return nil },
				})
				assert.NoError(t, err)
				_, err = p.GetSecret(context.Background(), secrets.Request{ID: mockSecretID})
				assert.ErrorContains(t, err, errGetSecret)
				assert.NoError(t, p.Close())
				r, err := parseOutput()
				require.NoError(t, err)
				require.Equal(t, 1, len(r.GetSecret))
			},
		},
		{
			// Note: The SIGINT error could only be returned by cmd.Wait() on linux.
			// So on other platforms this doesn't really test anything.
			name: "plugin ignoring SIGINT does not break the runtime",
			test: func(t *testing.T) {
				cmd, _ := dummyPluginCommand(t, dummyPluginCfg{
					Config: p.Config{
						Version: "my-version",
						Pattern: "foo-bar",
					},
					IgnoreSigint: true,
				})
				p, err := newLaunchedPlugin(cmd, setupValidator{
					name:          "dummy-plugin",
					out:           pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
					acceptPattern: func(secrets.Pattern) error { return nil },
				})
				assert.NoError(t, err)
				assert.NoError(t, p.Close())
				assert.NoError(t, checkClosed(p.Closed()))
			},
		},
		{
			name: "plugin process crashes unexpectedly",
			test: func(t *testing.T) {
				cmd, parseOutput := dummyPluginCommand(t, dummyPluginCfg{
					Config: p.Config{
						Version: "my-version",
						Pattern: "foo-bar",
					},
					IgnoreSigint: true,
				})
				p, err := newLaunchedPlugin(cmd, setupValidator{
					name:          "dummy-plugin",
					out:           pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
					acceptPattern: func(secrets.Pattern) error { return nil },
				})
				assert.NoError(t, err)
				_ = cmd.Process.Kill()
				_ = cmd.Process.Release()
				_, err = parseOutput()
				assert.ErrorContains(t, err, "failed to unmarshal ''")
				assert.ErrorContains(t, p.Close(), "plugin dummy-plugin crashed: signal: killed")
				assert.NoError(t, checkClosed(p.Closed()))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
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
				m := newMockExternalRuntime(l)
				go m.run()

				s, err := p.New(newMockedPlugin(), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				runErr, cancel := runAsyncWithTimeout(t.Context(), s.Run)
				t.Cleanup(cancel)

				r, err := m.getRuntime()
				assert.Equal(t, r.Data(), pluginData{
					name:       "my-plugin",
					pattern:    mockPattern,
					version:    "v1",
					pluginType: externalPlugin,
				})
				assert.NoError(t, err)
				e, err := r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
				assert.NoError(t, err)
				assert.Equal(t, mockSecretValue, string(e.Value))
				assert.NoError(t, r.Close())
				assert.NoError(t, checkClosed(r.Closed()))

				err = <-runErr
				assert.NoError(t, err)
			},
		},
		{
			name: "plugin returns error on GetSecret",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := newMockExternalRuntime(l)
				go m.run()

				s, err := p.New(newMockedPlugin(WithID("rewrite-id")), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				runErr, cancel := runAsyncWithTimeout(t.Context(), s.Run)
				t.Cleanup(cancel)

				r, err := m.getRuntime()
				assert.NoError(t, err)
				_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
				assert.ErrorContains(t, err, "id mismatch")
				assert.NoError(t, r.Close())
				assert.NoError(t, checkClosed(r.Closed()))

				err = <-runErr
				assert.NoError(t, err)
			},
		},
		{
			name: "cancelling plugin.run() shuts down the runtime",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := newMockExternalRuntime(l)
				go m.run()

				s, err := p.New(newMockedPlugin(), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})
				go func() {
					assert.NoError(t, s.Run(ctx))
					close(done)
				}()

				r, err := m.getRuntime()
				assert.NoError(t, err)
				e, err := r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
				assert.NoError(t, err)
				assert.Equal(t, mockSecretValue, string(e.Value))

				cancel()
				<-done
				assert.NoError(t, r.Close())
				assert.NoError(t, checkClosed(r.Closed()))
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
			require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0o755))
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

func checkClosed(closed <-chan struct{}) error {
	select {
	case <-closed:
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("plugin did not close after timeout")
	}
}

type mockExternalRuntime struct {
	l    net.Listener
	p    runtime
	err  error
	done chan struct{}
}

func newMockExternalRuntime(l net.Listener) *mockExternalRuntime {
	return &mockExternalRuntime{l: l, done: make(chan struct{})}
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

func (m *mockExternalRuntime) getRuntime() (runtime, error) {
	select {
	case <-m.done:
		return m.p, m.err
	case <-time.After(mockRuntimeTestTimeout):
		m.l.Close() // abort runtime
		return nil, errors.New("timeout")
	}
}
