package stub

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	nriNet "github.com/containerd/nri/pkg/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/pkg/adaptation"
	"github.com/docker/secrets-engine/pkg/secrets"
)

type mockPlugin struct {
}

func (m mockPlugin) GetSecret(context.Context, secrets.Request) (secrets.Envelope, error) {
	return secrets.Envelope{}, nil
}

func (m mockPlugin) Shutdown(context.Context) {
}

func cleanupEnv() {
	_ = os.Setenv(adaptation.PluginLaunchedByEngineVar, "")
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
				defer func() {
					os.Args = args
				}()
				os.Args = []string{"test-plugin"}
				os.Setenv("XDG_RUNTIME_DIR", os.TempDir())
				socketPath := adaptation.DefaultSocketPath()
				os.Remove(socketPath)
				require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0755))
				listener, err := net.Listen("unix", socketPath)
				if err != nil {
					t.Fatalf("listen failed: %v", err)
				}
				defer listener.Close()
				defer os.Remove(socketPath)

				m := mockPlugin{}
				c, err := newCfgForManualLaunch(m)
				assert.NoError(t, err)
				assert.Equal(t, "test-plugin", c.name)
				assert.Equal(t, adaptation.DefaultPluginRegistrationTimeout, c.registrationTimeout)
				assert.Equal(t, m, c.plugin)
				assert.NotNil(t, c.conn)
			},
		},
		{
			name: "with all custom options",
			test: func(t *testing.T) {
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				cfg, err := newCfgForManualLaunch(mockPlugin{},
					WithPluginName("test-plugin"),
					WithRegistrationTimeout(10*adaptation.DefaultPluginRegistrationTimeout),
					WithConnection(client),
				)
				assert.NoError(t, err)
				assert.Equal(t, "test-plugin", cfg.name)
				assert.Equal(t, 10*adaptation.DefaultPluginRegistrationTimeout, cfg.registrationTimeout)
				assert.Equal(t, client, cfg.conn)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

func Test_restoreConfig(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "no config from the engine",
			test: func(t *testing.T) {
				_, err := restoreConfig(mockPlugin{})
				assert.ErrorIs(t, err, errPluginNotLaunchedByEngine)
			},
		},
		{
			name: "invalid config from the engine",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginLaunchedByEngineVar, "test-plugin")
				_, err := restoreConfig(mockPlugin{})
				assert.Error(t, err)
			},
		},
		{
			name: "valid config",
			test: func(t *testing.T) {
				sockets, err := nriNet.NewSocketPair()
				require.NoError(t, err)
				defer sockets.Close()
				conn, err := sockets.LocalConn()
				require.NoError(t, err)
				defer conn.Close()
				peerFile := sockets.PeerFile()
				defer peerFile.Close()
				defer cleanupEnv()
				engineCfg := adaptation.PluginConfigFromEngine{
					Name:                "test-plugin",
					RegistrationTimeout: 10 * adaptation.DefaultPluginRegistrationTimeout,
					Fd:                  int(peerFile.Fd()),
				}
				cfgString, err := engineCfg.ToString()
				require.NoError(t, err)
				_ = os.Setenv(adaptation.PluginLaunchedByEngineVar, cfgString)

				cfg, err := restoreConfig(mockPlugin{})
				assert.NoError(t, err)
				assert.Equal(t, "test-plugin", cfg.name)
				assert.Equal(t, 10*adaptation.DefaultPluginRegistrationTimeout, cfg.registrationTimeout)
				defer cfg.conn.Close()
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
