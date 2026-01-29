package launcher

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	p "github.com/docker/secrets-engine/plugin"
	"github.com/docker/secrets-engine/runtime/internal/mocks"
	"github.com/docker/secrets-engine/runtime/internal/plugin"
	"github.com/docker/secrets-engine/runtime/internal/testdummy"
	et "github.com/docker/secrets-engine/runtime/internal/testhelper"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/ipc"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

const (
	mockEngineName    = "mockEngineName"
	mockEngineVersion = "mockEngineVersion"
	mockSecretValue   = "mockSecretValue"
)

var (
	mockPattern       = secrets.MustParsePattern("mockPattern")
	mockValidVersion  = api.MustNewVersion("v7")
	mockSecretPattern = secrets.MustParsePattern("mockSecretID")
)

func TestMain(m *testing.M) {
	testdummy.TestMain(m)
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
					Secrets: map[string]string{
						testdummy.MockSecretID.String(): testdummy.MockSecretValue,
					},
				})
				p, err := newLaunchedPlugin(
					NewRuntimeConfig(
						pluginNameFromTestName(t),
						plugin.ConfigOut{
							EngineName:     mockEngineName,
							EngineVersion:  mockEngineVersion,
							RequestTimeout: 30 * time.Second,
						},
						et.NewEngineConfig(t),
					),
					cmd,
				)
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
				p, err := newLaunchedPlugin(
					NewRuntimeConfig(
						pluginNameFromTestName(t),
						plugin.ConfigOut{EngineName: mockEngineName, EngineVersion: mockEngineVersion, RequestTimeout: 30 * time.Second},
						et.NewEngineConfig(t),
					),
					cmd,
				)
				require.NoError(t, err)
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
				p, err := newLaunchedPlugin(
					NewRuntimeConfig(
						pluginNameFromTestName(t),
						plugin.ConfigOut{EngineName: mockEngineName, EngineVersion: mockEngineVersion, RequestTimeout: 30 * time.Second},
						et.NewEngineConfig(t),
					),
					cmd,
				)
				require.NoError(t, err)
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
				p, err := newLaunchedPlugin(
					NewRuntimeConfig(
						pluginNameFromTestName(t),
						plugin.ConfigOut{EngineName: mockEngineName, EngineVersion: mockEngineVersion, RequestTimeout: 30 * time.Second},
						et.NewEngineConfig(t),
					),
					cmd,
				)
				require.NoError(t, err)
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
				p, err := newLaunchedPlugin(
					NewRuntimeConfig(
						pluginNameFromTestName(t),
						plugin.ConfigOut{EngineName: mockEngineName, EngineVersion: mockEngineVersion, RequestTimeout: 30 * time.Second},
						et.NewEngineConfig(t),
					),
					cmd,
				)
				require.NoError(t, err)
				_, err = p.GetSecrets(context.Background(), testdummy.MockSecretPattern)
				require.NoError(t, err)
				require.NoError(t, p.Watcher().Kill())
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
				m := newMockExternalRuntime(t, l)

				config := testExternalPluginConfig(t)
				s, err := p.New(mocks.NewMockedPlugin(), config, p.WithPluginName("my-plugin"), p.WithConnection(conn))
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
				m := newMockExternalRuntime(t, l)
				s, err := p.New(mocks.NewMockedPlugin(), testExternalPluginConfig(t), p.WithPluginName("my-plugin"), p.WithConnection(conn))
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
				m := newMockExternalRuntime(t, l)

				s, err := p.New(mocks.NewMockedPlugin(), testExternalPluginConfig(t), p.WithPluginName("my-plugin"), p.WithConnection(conn))
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
				m := newMockExternalRuntime(t, l)

				doneRuntime := make(chan struct{})
				go func() {
					_, err := m.waitForNextRuntimeWithTimeout()
					assert.ErrorContains(t, err, "invalid pattern")
					close(doneRuntime)
				}()

				s, err := p.New(mocks.NewMockedPlugin(), p.Config{
					Version: mockValidVersion,
					Pattern: &maliciousPattern{},
					Logger:  testhelper.TestLogger(t),
				}, p.WithPluginName("my-plugin"), p.WithConnection(conn))
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

func (m maliciousPattern) ExpandID(secrets.ID) (secrets.ID, error) {
	panic("implement me")
}

func (m maliciousPattern) ExpandPattern(secrets.Pattern) (secrets.Pattern, error) {
	panic("implement me")
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
	t         *testing.T
	server    *http.Server
	ch        chan nextConn
	serverErr chan error
}

type nextConn struct {
	conn io.ReadWriteCloser
	done func()
}

func newMockExternalRuntime(t *testing.T, l net.Listener) *mockExternalRuntime {
	httpMux := http.NewServeMux()
	ch := make(chan nextConn)
	httpMux.Handle(ipc.NewHijackAcceptor(testhelper.TestLogger(t), func(_ context.Context, conn io.ReadWriteCloser) {
		wait := make(chan struct{})
		ch <- nextConn{conn: conn, done: sync.OnceFunc(func() { close(wait) })}
		<-wait
	}))
	serverErr := make(chan error, 1)
	server := &http.Server{Handler: httpMux}
	go func() {
		serverErr <- server.Serve(l)
	}()
	return &mockExternalRuntime{t: t, server: server, ch: ch, serverErr: serverErr}
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
	r, err := NewExternalPlugin(
		NewRuntimeConfig(
			"", // TODO:(@benehiko) this needs to be empty otherwise the validation step will compare
			// the plugin name and will fail "launched plugin name cannot be changed"...
			plugin.ConfigOut{EngineName: "test-runtime", EngineVersion: "v1.0.0", RequestTimeout: 30 * time.Second},
			et.NewEngineConfig(m.t),
		),
		item.conn)
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
