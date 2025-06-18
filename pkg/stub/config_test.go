package stub

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	nriNet "github.com/containerd/nri/pkg/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/pkg/adaptation"
	"github.com/docker/secrets-engine/pkg/api"
	"github.com/docker/secrets-engine/pkg/secrets"
)

type mockPlugin struct {
}

func (m mockPlugin) GetSecret(context.Context, secrets.Request) (secrets.Envelope, error) {
	return secrets.Envelope{}, nil
}

func (m mockPlugin) Shutdown(context.Context) {
}

func Test_newCfg(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "no options allowed when launched from secrets engine",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_, err := newCfg(mockPlugin{}, WithPluginName("test-plugin"))
				assert.ErrorContains(t, err, "cannot use manual launch options")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

func cleanupEnv() {
	_ = os.Setenv(adaptation.PluginNameEnvVar, "")
	_ = os.Setenv(adaptation.PluginIdxEnvVar, "")
	_ = os.Setenv(adaptation.PluginRegistrationTimeoutEnvVar, "")
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
				os.Args = []string{"10-test-plugin"}
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

				cfg, err := newCfgForManualLaunch(m)
				assert.NoError(t, err)
				assert.Equal(t, "10", cfg.identity.idx)
				assert.Equal(t, "test-plugin", cfg.identity.name)
				assert.Equal(t, adaptation.DefaultPluginRegistrationTimeout, cfg.registrationTimeout)
				assert.NotNil(t, cfg.conn)
				assert.Equal(t, m, cfg.plugin)
			},
		},
		{
			name: "no options just defaults but filename does not contain index",
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

				_, err = newCfgForManualLaunch(mockPlugin{})
				assert.ErrorIs(t, err, &api.ErrInvalidPluginIndex{Actual: "test", Msg: "must be two digits"})
			},
		},
		{
			name: "without name",
			test: func(t *testing.T) {
				var args []string
				copy(args, os.Args)
				defer func() {
					os.Args = args
				}()
				os.Args = []string{"test-plugin"}
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				cfg, err := newCfgForManualLaunch(mockPlugin{}, WithPluginIdx("10"), WithConnection(client))
				assert.NoError(t, err)
				assert.Equal(t, "10", cfg.identity.idx)
				assert.Equal(t, "test-plugin", cfg.identity.name)
				assert.Equal(t, client, cfg.conn)
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
					WithPluginIdx("10"),
					WithRegistrationTimeout(10*adaptation.DefaultPluginRegistrationTimeout),
					WithConnection(client),
				)
				assert.NoError(t, err)
				assert.Equal(t, "10", cfg.identity.idx)
				assert.Equal(t, "test-plugin", cfg.identity.name)
				assert.Equal(t, 10*adaptation.DefaultPluginRegistrationTimeout, cfg.registrationTimeout)
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
			name: "name missing",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_, err := restoreConfig()
				assert.ErrorIs(t, err, errPluginNameNotSet)
			},
		},
		{
			name: "index missing",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_, err := restoreConfig()
				assert.ErrorIs(t, err, errPluginIdxNotSet)
			},
		},
		{
			name: "invalid index",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_ = os.Setenv(adaptation.PluginIdxEnvVar, "invalid-index")
				_, err := restoreConfig()
				assert.ErrorIs(t, err, &api.ErrInvalidPluginIndex{Actual: "invalid-index", Msg: "must be two digits"})
			},
		},
		{
			name: "registration timeout missing",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_ = os.Setenv(adaptation.PluginIdxEnvVar, "10")
				_, err := restoreConfig()
				assert.ErrorIs(t, err, errPluginRegistrationTimeoutNotSet)
			},
		},
		{
			name: "invalid registration timeout",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_ = os.Setenv(adaptation.PluginIdxEnvVar, "10")
				_ = os.Setenv(adaptation.PluginRegistrationTimeoutEnvVar, "10")
				_, err := restoreConfig()
				assert.ErrorContains(t, err, "invalid registration timeout")
			},
		},
		{
			name: "socket fd missing",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_ = os.Setenv(adaptation.PluginIdxEnvVar, "10")
				_ = os.Setenv(adaptation.PluginRegistrationTimeoutEnvVar, "10s")
				_, err := restoreConfig()
				assert.ErrorIs(t, err, errPluginSocketNotSet)
			},
		},
		{
			name: "valid config",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_ = os.Setenv(adaptation.PluginIdxEnvVar, "10")
				_ = os.Setenv(adaptation.PluginRegistrationTimeoutEnvVar, "10s")

				sockets, err := nriNet.NewSocketPair()
				require.NoError(t, err)
				defer sockets.Close()
				conn, err := sockets.LocalConn()
				require.NoError(t, err)
				defer conn.Close()
				peerFile := sockets.PeerFile()
				defer peerFile.Close()
				_ = os.Setenv(adaptation.PluginSocketEnvVar, strconv.Itoa(int(peerFile.Fd())))

				cfg, err := restoreConfig()
				assert.NoError(t, err)
				assert.Equal(t, "test-plugin", cfg.identity.name)
				assert.Equal(t, "10", cfg.identity.idx)
				assert.Equal(t, 10*time.Second, cfg.timeout)
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
