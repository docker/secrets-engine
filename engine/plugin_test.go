package engine

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/internal/ipc"
	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/internal/testhelper"
	p "github.com/docker/secrets-engine/plugin"
)

const (
	mockEngineName         = "mockEngineName"
	mockEngineVersion      = "mockEngineVersion"
	mockRuntimeTestTimeout = 10 * time.Second
)

type mockedPlugin struct {
	pattern secrets.Pattern
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

func WithPattern(pattern secrets.Pattern) MockedPluginOption {
	return func(mp *mockedPlugin) {
		mp.pattern = pattern
	}
}

func WithID(id secrets.ID) MockedPluginOption {
	return func(mp *mockedPlugin) {
		mp.id = id
	}
}

func (m *mockedPlugin) GetSecret(context.Context, secrets.Request) (secrets.Envelope, error) {
	return secrets.Envelope{ID: m.id, Value: []byte(mockSecretValue)}, nil
}

func (m *mockedPlugin) Config() p.Config {
	return p.Config{
		Version: "v1",
		Pattern: m.pattern,
	}
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
	t.Parallel()
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "engine launched plugin",
			test: func(t *testing.T) {
				pattern := secrets.Pattern("foo-bar")
				version := "my-version"
				cmd, parseOutput := dummyPluginCommand(t, dummyPluginCfg{
					Config: p.Config{
						Version: version,
						Pattern: pattern,
					},
					E: []secrets.Envelope{{ID: mockSecretID, Value: []byte(mockSecretValue)}},
				})
				p, err := newLaunchedPlugin(cmd, runtimeCfg{
					name: "dummy-plugin",
					out:  pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
				})
				assert.NoError(t, err)
				assert.Equal(t, p.Data(), pluginData{
					name:       "dummy-plugin",
					pattern:    pattern,
					version:    version,
					pluginType: internalPlugin,
				})
				s, err := p.GetSecret(context.Background(), secrets.Request{ID: mockSecretID})
				assert.NoError(t, err)
				assert.Equal(t, mockSecretValue, string(s.Value))
				assert.NoError(t, p.Close())
				assert.NoError(t, testhelper.WaitForWithTimeout(p.Closed()))
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
				p, err := newLaunchedPlugin(cmd, runtimeCfg{
					name: "dummy-plugin",
					out:  pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
				})
				assert.NoError(t, err)
				_, err = p.GetSecret(context.Background(), secrets.Request{ID: mockSecretID})
				assert.ErrorContains(t, err, errGetSecret)
				assert.NoError(t, p.Close())
				r, err := parseOutput()
				// TODO: investigate
				// This keeps randomly failing on CI with:
				// failed to unmarshal '': unexpected end of JSON input
				//
				// It means the plugin hasn't been shutdown yet though we believe it should have
				// or the plugin somehow didn't manage to send stuff to STDOUT.
				// Either way, when we try to parse what we believe is STDOUT, it's empty.
				require.NoError(t, err, "could not parse plugin binary output")
				require.Equal(t, 1, len(r.GetSecret))
			},
		},
		{
			// Note: The SIGINT/STATUS_CONTROL_C_EXIT error could only be returned by cmd.Wait() on linux/windows.
			// On darwin this doesn't really test anything.
			// TODO(investigate): On windows cmd.Wait() returning STATUS_CONTROL_C_EXIT is very unreliable through this test.
			name: "plugin ignoring SIGINT does not break the runtime",
			test: func(t *testing.T) {
				cmd, _ := dummyPluginCommand(t, dummyPluginCfg{
					Config: p.Config{
						Version: "my-version",
						Pattern: "foo-bar",
					},
					IgnoreSigint: true,
				})
				p, err := newLaunchedPlugin(cmd, runtimeCfg{
					name: "dummy-plugin",
					out:  pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
				})
				assert.NoError(t, err)
				assert.NoError(t, p.Close())
				assert.NoError(t, testhelper.WaitForWithTimeout(p.Closed()))
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
				p, err := newLaunchedPlugin(cmd, runtimeCfg{
					name: "dummy-plugin",
					out:  pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
				})
				assert.NoError(t, err)
				_ = cmd.Process.Kill()
				_ = cmd.Process.Release()
				assert.ErrorContains(t, p.Close(), "plugin dummy-plugin crashed:")
				assert.NoError(t, testhelper.WaitForWithTimeout(p.Closed()))
				_, err = parseOutput()
				assert.ErrorContains(t, err, "failed to unmarshal ''")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

func Test_newExternalPlugin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		test func(t *testing.T, listener net.Listener, conn net.Conn)
	}{
		{
			name: "create external plugin",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := newMockExternalRuntime(l)

				plugin := newMockedPlugin()
				s, err := p.New(plugin, p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				runErr, cancel := runAsyncWithTimeout(t.Context(), s.Run)
				t.Cleanup(cancel)

				r, err := m.waitForNextRuntimeWithTimeout()
				require.NoError(t, err)
				assert.Equal(t, r.Data(), pluginData{
					name:       "my-plugin",
					pattern:    mockPattern,
					version:    "v1",
					pluginType: externalPlugin,
				})
				e, err := r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
				assert.NoError(t, err)
				assert.Equal(t, mockSecretValue, string(e.Value))
				assert.NoError(t, r.Close())
				assert.NoError(t, testhelper.WaitForWithTimeout(r.Closed()))

				err = <-runErr
				assert.NoError(t, err)
				assert.ErrorIs(t, m.shutdown(), http.ErrServerClosed)
			},
		},
		{
			name: "plugin returns error on GetSecret",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := newMockExternalRuntime(l)

				s, err := p.New(newMockedPlugin(WithID("rewrite-id")), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				runErr, cancel := runAsyncWithTimeout(t.Context(), s.Run)
				t.Cleanup(cancel)

				r, err := m.waitForNextRuntimeWithTimeout()
				require.NoError(t, err)
				_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
				assert.ErrorContains(t, err, "id mismatch")
				assert.NoError(t, r.Close())
				assert.NoError(t, testhelper.WaitForWithTimeout(r.Closed()))

				err = <-runErr
				assert.NoError(t, err)
				assert.ErrorIs(t, m.shutdown(), http.ErrServerClosed)
			},
		},
		{
			name: "cancelling plugin.run() shuts down the runtime",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := newMockExternalRuntime(l)

				s, err := p.New(newMockedPlugin(), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})
				go func() {
					assert.NoError(t, s.Run(ctx))
					close(done)
				}()

				r, err := m.waitForNextRuntimeWithTimeout()
				require.NoError(t, err)
				e, err := r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
				assert.NoError(t, err)
				assert.Equal(t, mockSecretValue, string(e.Value))

				cancel()
				<-done
				assert.NoError(t, testhelper.WaitForWithTimeout(r.Closed()))
				assert.NoError(t, r.Close())
				assert.ErrorIs(t, m.shutdown(), http.ErrServerClosed)
			},
		},
		{
			name: "plugins with invalid patterns are rejected",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := newMockExternalRuntime(l)

				doneRuntime := make(chan struct{})
				go func() {
					_, err := m.waitForNextRuntimeWithTimeout()
					assert.ErrorContains(t, err, "invalid pattern")
					close(doneRuntime)
				}()

				s, err := p.New(newMockedPlugin(WithPattern("a*a")), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				assert.ErrorContains(t, s.Run(t.Context()), "invalid pattern")
				<-doneRuntime
				assert.ErrorIs(t, m.shutdown(), http.ErrServerClosed)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socketPath := randString(6) + ".sock" // avoid socket name clashes with parallel running tests
			l, err := net.Listen("unix", socketPath)
			require.NoError(t, err)
			conn, err := net.Dial("unix", socketPath)
			require.NoError(t, err)
			tt.test(t, l, conn)
			conn.Close()
			l.Close()
		})
	}
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
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
	server    *http.Server
	chConn    chan net.Conn
	serverErr chan error
}

func newMockExternalRuntime(l net.Listener) *mockExternalRuntime {
	httpMux := http.NewServeMux()
	chConn := make(chan net.Conn)
	httpMux.Handle(ipc.NewHijackAcceptor(func(conn net.Conn) { chConn <- conn }))
	serverErr := make(chan error, 1)
	server := &http.Server{Handler: httpMux}
	go func() {
		serverErr <- server.Serve(l)
	}()
	return &mockExternalRuntime{server: server, chConn: chConn, serverErr: serverErr}
}

func (m *mockExternalRuntime) shutdown() error {
	m.server.Close()
	return testhelper.WaitForWithTimeout(m.serverErr)
}

func (m *mockExternalRuntime) waitForNextRuntimeWithTimeout() (runtime, error) {
	conn, err := testhelper.WaitForWithTimeoutV(m.chConn)
	if err != nil {
		return nil, err
	}
	return newExternalPlugin(conn, runtimeCfg{
		out: pluginCfgOut{engineName: "test-engine", engineVersion: "1.0.0", requestTimeout: 30 * time.Second},
	})
}
