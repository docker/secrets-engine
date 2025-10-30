package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/engine/internal/testdummy"
	p "github.com/docker/secrets-engine/plugin"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/ipc"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

const (
	mockEngineName    = "mockEngineName"
	mockEngineVersion = "mockEngineVersion"
)

var mockPattern = secrets.MustParsePattern("mockPattern")

type mockedPlugin struct {
	id secrets.ID
}

type MockedPluginOption func(*mockedPlugin)

func newMockedPlugin(options ...MockedPluginOption) *mockedPlugin {
	m := &mockedPlugin{
		id: mockSecretIDNew,
	}
	for _, opt := range options {
		opt(m)
	}
	return m
}

func WithID(id secrets.ID) MockedPluginOption {
	return func(mp *mockedPlugin) {
		mp.id = id
	}
}

func (m *mockedPlugin) GetSecrets(_ context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	if pattern.Match(m.id) {
		return []secrets.Envelope{{ID: m.id, Value: []byte(mockSecretValue)}}, nil
	}
	return nil, secrets.ErrNotFound
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
		testdummy.PluginProcessFromBinaryName(binaryName)
	} else if os.Getenv("RUN_AS_DUMMY_PLUGIN") != "" {
		testdummy.PluginProcess()
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
				pattern := "foo-bar"
				version := api.MustNewVersion("v2")
				cmd, parseOutput := testdummy.PluginCommand(t, testdummy.PluginCfg{
					Version: version.String(),
					Pattern: pattern,
					Secrets: map[string]string{testdummy.MockSecretID.String(): testdummy.MockSecretValue},
				})
				p, err := newLaunchedPlugin(testhelper.TestLogger(t), cmd, runtimeCfg{
					name: pluginNameFromTestName(t),
					out:  pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
				})
				require.NoError(t, err)
				assert.Equal(t, pluginNameFromTestName(t), p.Name().String())
				assert.Equal(t, version.String(), p.Version().String())
				assert.Equal(t, pattern, p.Pattern().String())
				s, err := p.GetSecrets(context.Background(), testdummy.MockSecretPattern)
				require.NoError(t, err)
				require.NotEmpty(t, s)
				assert.Equal(t, testdummy.MockSecretValue, string(s[0].Value))
				assert.NoError(t, p.Close())
				assert.NoError(t, testhelper.WaitForClosedWithTimeout(p.Closed()))
				r, err := parseOutput()
				require.NoError(t, err)
				require.Equal(t, 1, len(r.GetSecret))
				assert.Equal(t, testdummy.MockSecretID.String(), r.GetSecret[0])

				t.Logf("plugin binary output:\n%s", r.Log)
			},
		},
		{
			name: "plugin returns no secret but an error",
			test: func(t *testing.T) {
				errGetSecret := "you do not get my secret"
				cmd, parseOutput := testdummy.PluginCommand(t, testdummy.PluginCfg{
					Version:      "v1",
					Pattern:      "foo-bar",
					ErrGetSecret: errGetSecret,
				})
				p, err := newLaunchedPlugin(testhelper.TestLogger(t), cmd, runtimeCfg{
					name: pluginNameFromTestName(t),
					out:  pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
				})
				assert.NoError(t, err)
				_, err = p.GetSecrets(context.Background(), testdummy.MockSecretPattern)
				assert.ErrorContains(t, err, errGetSecret)
				assert.NoError(t, p.Close())
				r, err := parseOutput()
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
				cmd, _ := testdummy.PluginCommand(t, testdummy.PluginCfg{
					Version:      "v1",
					Pattern:      "foo-bar",
					IgnoreSigint: true,
				})
				p, err := newLaunchedPlugin(testhelper.TestLogger(t), cmd, runtimeCfg{
					name: pluginNameFromTestName(t),
					out:  pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
				})
				assert.NoError(t, err)
				assert.NoError(t, p.Close())
				assert.NoError(t, testhelper.WaitForClosedWithTimeout(p.Closed()))
			},
		},
		{
			name: "plugin process crashes unexpectedly",
			test: func(t *testing.T) {
				cmd, parseOutput := testdummy.PluginCommand(t, testdummy.PluginCfg{
					Version:      "v1",
					Pattern:      "foo-bar",
					IgnoreSigint: true,
				})
				p, err := newLaunchedPlugin(testhelper.TestLogger(t), cmd, runtimeCfg{
					name: pluginNameFromTestName(t),
					out:  pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
				})
				assert.NoError(t, err)
				_ = cmd.Process.Kill()
				assert.ErrorContains(t, p.Close(), fmt.Sprintf("plugin %s crashed:", pluginNameFromTestName(t)))
				assert.NoError(t, testhelper.WaitForClosedWithTimeout(p.Closed()))
				_, err = parseOutput()
				assert.ErrorContains(t, err, "failed to unmarshal ''")
			},
		},
		{
			name: "plugin process exists unexpectedly",
			test: func(t *testing.T) {
				cmd, parseOutput := testdummy.PluginCommand(t, testdummy.PluginCfg{
					Version: "v2",
					Pattern: "foo-bar",
					Secrets: map[string]string{testdummy.MockSecretID.String(): testdummy.MockSecretValue},
				})
				p, err := newLaunchedPlugin(testhelper.TestLogger(t), cmd, runtimeCfg{
					name: pluginNameFromTestName(t),
					out:  pluginCfgOut{engineName: mockEngineName, engineVersion: mockEngineVersion, requestTimeout: 30 * time.Second},
				})
				assert.NoError(t, err)
				_, err = p.GetSecrets(context.Background(), testdummy.MockSecretPattern)
				assert.NoError(t, err)
				require.NoError(t, getProc(t, p).kill())
				assert.NoError(t, testhelper.WaitForClosedWithTimeout(p.Closed()))
				assert.ErrorContains(t, p.Close(), "stopped unexpectedly")
				_, err = p.GetSecrets(context.Background(), testdummy.MockSecretPattern)
				assert.ErrorIs(t, err, yamux.ErrSessionShutdown)
				_, err = parseOutput()
				assert.ErrorContains(t, err, "failed to unmarshal ''")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

func getProc(t *testing.T, r plugin.Runtime) proc {
	t.Helper()
	impl, ok := r.(*runtimeImpl)
	require.True(t, ok)
	require.NotNil(t, impl)
	p, ok := impl.cmd.(*cmdWatchWrapper)
	require.True(t, ok)
	return p.p
}

func pluginNameFromTestName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("plugin-%s", strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_")))
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
				m := newMockExternalRuntime(testhelper.TestLogger(t), l)

				config := testExternalPluginConfig(t)
				s, err := p.New(newMockedPlugin(), config, p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				runErr := runAsync(t.Context(), s.Run)

				r, err := m.waitForNextRuntimeWithTimeout()
				require.NoError(t, err)
				assert.Equal(t, "my-plugin", r.Name().String())
				assert.Equal(t, config.Version.String(), r.Version().String())
				assert.Equal(t, mockPattern.String(), r.Pattern().String())
				e, err := r.GetSecrets(t.Context(), mockSecretPattern)
				require.NoError(t, err)
				require.NotEmpty(t, e)
				assert.Equal(t, mockSecretValue, string(e[0].Value))
				assert.NoError(t, r.Close())
				assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))

				assert.NoError(t, testhelper.WaitForErrorWithTimeout(runErr))
				assert.ErrorIs(t, m.shutdown(), http.ErrServerClosed)
			},
		},
		{
			name: "secret not found",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := newMockExternalRuntime(testhelper.TestLogger(t), l)
				s, err := p.New(newMockedPlugin(), testExternalPluginConfig(t), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				runErr := runAsync(t.Context(), s.Run)

				r, err := m.waitForNextRuntimeWithTimeout()
				require.NoError(t, err)
				_, err = r.GetSecrets(t.Context(), secrets.MustParsePattern("bar"))
				assert.ErrorIs(t, err, secrets.ErrNotFound)
				assert.NoError(t, r.Close())
				assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))

				err = <-runErr
				assert.NoError(t, err)
				assert.ErrorIs(t, m.shutdown(), http.ErrServerClosed)
			},
		},
		{
			name: "cancelling plugin.run() shuts down the runtime",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := newMockExternalRuntime(testhelper.TestLogger(t), l)

				s, err := p.New(newMockedPlugin(), testExternalPluginConfig(t), p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})
				go func() {
					assert.NoError(t, s.Run(ctx))
					close(done)
				}()

				r, err := m.waitForNextRuntimeWithTimeout()
				require.NoError(t, err)
				e, err := r.GetSecrets(t.Context(), mockSecretPattern)
				require.NoError(t, err)
				require.NotEmpty(t, e)
				assert.Equal(t, mockSecretValue, string(e[0].Value))

				cancel()
				<-done
				assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
				assert.NoError(t, r.Close())
				assert.ErrorIs(t, m.shutdown(), http.ErrServerClosed)
			},
		},
		{
			name: "plugins with invalid patterns are rejected",
			test: func(t *testing.T, l net.Listener, conn net.Conn) {
				t.Helper()
				m := newMockExternalRuntime(testhelper.TestLogger(t), l)

				doneRuntime := make(chan struct{})
				go func() {
					_, err := m.waitForNextRuntimeWithTimeout()
					assert.ErrorContains(t, err, "invalid pattern")
					close(doneRuntime)
				}()

				s, err := p.New(newMockedPlugin(), p.Config{Version: mockValidVersion, Pattern: &maliciousPattern{}, Logger: testhelper.TestLogger(t)}, p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				assert.ErrorContains(t, s.Run(t.Context()), "invalid pattern")
				<-doneRuntime
				assert.ErrorIs(t, m.shutdown(), http.ErrServerClosed)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socketPath := testhelper.RandomShortSocketName()
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

type maliciousPattern struct{}

func (m maliciousPattern) Includes(secrets.Pattern) bool {
	panic("implement me")
}

func (m maliciousPattern) Match(secrets.ID) bool {
	panic("implement me")
}

func (m maliciousPattern) String() string {
	return "a*a"
}

func testExternalPluginConfig(t *testing.T) p.Config {
	t.Helper()
	return p.Config{Version: api.MustNewVersion("v4"), Pattern: mockPattern, Logger: testhelper.TestLogger(t)}
}

func runAsync(ctx context.Context, run func(ctx context.Context) error) chan error {
	runErr := make(chan error)
	go func() {
		runErr <- run(ctx)
	}()
	return runErr
}

type mockExternalRuntime struct {
	server    *http.Server
	ch        chan nextConn
	serverErr chan error
	logger    logging.Logger
}

type nextConn struct {
	conn io.ReadWriteCloser
	done func()
}

func newMockExternalRuntime(logger logging.Logger, l net.Listener) *mockExternalRuntime {
	httpMux := http.NewServeMux()
	ch := make(chan nextConn)
	httpMux.Handle(ipc.NewHijackAcceptor(logger, func(_ context.Context, conn io.ReadWriteCloser) {
		wait := make(chan struct{})
		ch <- nextConn{conn: conn, done: sync.OnceFunc(func() { close(wait) })}
		<-wait
	}))
	serverErr := make(chan error, 1)
	server := &http.Server{Handler: httpMux}
	go func() {
		serverErr <- server.Serve(l)
	}()
	return &mockExternalRuntime{logger: logger, server: server, ch: ch, serverErr: serverErr}
}

func (m *mockExternalRuntime) shutdown() error {
	m.server.Close()
	return testhelper.WaitForErrorWithTimeout(m.serverErr)
}

func (m *mockExternalRuntime) waitForNextRuntimeWithTimeout() (plugin.Runtime, error) {
	item, err := testhelper.WaitForWithTimeoutV(m.ch)
	if err != nil {
		return nil, err
	}
	r, err := newExternalPlugin(m.logger, item.conn, runtimeCfg{
		out: pluginCfgOut{engineName: "test-engine", engineVersion: "v1.0.0", requestTimeout: 30 * time.Second},
	})
	if err != nil {
		item.done()
		return nil, err
	}
	go func() {
		<-r.Closed()
		item.done()
	}()
	return r, nil
}
