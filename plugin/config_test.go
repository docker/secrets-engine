package plugin

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	nriNet "github.com/containerd/nri/pkg/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/ipc"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

var _ ExternalPlugin = &mockPlugin{}

type mockPlugin struct{}

func (m *mockPlugin) GetSecrets(context.Context, secrets.Pattern) ([]secrets.Envelope, error) {
	return []secrets.Envelope{}, nil
}

func Test_newCfgForManualLaunch(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "no options just defaults",
			test: func(t *testing.T) {
				var args []string
				copy(args, os.Args)
				t.Cleanup(func() {
					os.Args = args
				})
				os.Args = []string{"test-plugin"}
				t.Setenv("XDG_RUNTIME_DIR", os.TempDir())
				socketPath := api.DefaultSocketPath()
				os.Remove(socketPath)
				require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0o755))
				listener, err := net.Listen("unix", socketPath)
				if err != nil {
					t.Fatalf("listen failed: %v", err)
				}
				go runUncheckedDummyAcceptor(testhelper.TestLogger(t), listener)
				t.Cleanup(func() {
					listener.Close()
					os.Remove(socketPath)
				})

				m := &mockPlugin{}
				c, err := newCfgForManualLaunch(m)
				assert.NoError(t, err)
				assert.Equal(t, "test-plugin", c.name)
				assert.Equal(t, api.DefaultPluginRegistrationTimeout, c.registrationTimeout)
				assert.Equal(t, m, c.plugin)
				assert.NotNil(t, c.conn)
			},
		},
		{
			name: "with all custom options",
			test: func(t *testing.T) {
				socket := testhelper.RandomShortSocketName()
				l, err := net.Listen("unix", socket)
				require.NoError(t, err)
				t.Cleanup(func() { l.Close() })
				go runUncheckedDummyAcceptor(testhelper.TestLogger(t), l)
				conn, err := net.Dial("unix", socket)
				require.NoError(t, err)
				t.Cleanup(func() { conn.Close() })

				cfg, err := newCfgForManualLaunch(&mockPlugin{},
					WithPluginName("test-plugin"),
					WithRegistrationTimeout(10*api.DefaultPluginRegistrationTimeout),
					WithConnection(conn),
				)
				assert.NoError(t, err)
				assert.Equal(t, "test-plugin", cfg.name)
				assert.Equal(t, 10*api.DefaultPluginRegistrationTimeout, cfg.registrationTimeout)
				assert.NotNil(t, cfg.conn)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

// We on purpose never actually deal with accepted hijacked connections or server errors
// as in the context of where this function is used we don't care.
func runUncheckedDummyAcceptor(logger logging.Logger, listener net.Listener) {
	httpMux := http.NewServeMux()
	httpMux.Handle(ipc.NewHijackAcceptor(logger, func(context.Context, io.ReadWriteCloser) {}))
	server := &http.Server{Handler: httpMux}
	go func() {
		_ = server.Serve(listener)
	}()
}

func Test_restoreConfig(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "no config from the engine",
			test: func(t *testing.T) {
				_, err := restoreConfig(&mockPlugin{})
				assert.ErrorIs(t, err, errPluginNotLaunchedByEngine)
			},
		},
		{
			name: "invalid config from the engine",
			test: func(t *testing.T) {
				t.Setenv(api.PluginLaunchedByEngineVar, "test-plugin")
				_, err := restoreConfig(&mockPlugin{})
				assert.Error(t, err)
			},
		},
		{
			name: "valid config",
			test: func(t *testing.T) {
				sockets, err := nriNet.NewSocketPair()
				require.NoError(t, err)
				t.Cleanup(func() { sockets.Close() })
				conn, err := sockets.LocalConn()
				require.NoError(t, err)
				t.Cleanup(func() { conn.Close() })
				peerFile := sockets.PeerFile()
				t.Cleanup(func() { peerFile.Close() })
				engineCfg := ipc.PluginConfigFromEngine{
					Name:                "test-plugin",
					RegistrationTimeout: 10 * api.DefaultPluginRegistrationTimeout,
					Custom:              ipc.FakeTestCustom(int(peerFile.Fd())),
				}
				cfgString, err := engineCfg.ToString()
				require.NoError(t, err)
				t.Setenv(api.PluginLaunchedByEngineVar, cfgString)

				cfg, err := restoreConfig(&mockPlugin{})
				assert.NoError(t, err)
				assert.Equal(t, "test-plugin", cfg.name)
				assert.Equal(t, 10*api.DefaultPluginRegistrationTimeout, cfg.registrationTimeout)
				t.Cleanup(func() { cfg.conn.Close() })
				msg := []byte("hello test")
				go func() {
					_, err := conn.Write(msg)
					assert.NoError(t, err)
				}()
				buf := make([]byte, len(msg))
				n, err := cfg.conn.Read(buf)
				assert.NoError(t, err)
				assert.Equal(t, msg, buf[:n])
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}
