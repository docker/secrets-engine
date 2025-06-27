package adaptation

import (
	"context"
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
	mockSecretValue = "mockSecretValue"
	mockSecretID    = secrets.ID("mockSecretID")
)

var (
	mockPlugin = &mockedPlugin{
		pattern: "*",
		id:      mockSecretID,
	}
)

type mockedPlugin struct {
	pattern      string
	id           secrets.ID
	configureErr error
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
				doneRuntime := make(chan struct{})
				go func() {
					conn, err := l.Accept()
					require.NoError(t, err)

					p, err := newExternalPlugin(conn, setupValidator{
						out:           pluginCfgOut{engineName: "test-engine", engineVersion: "1.0.0", requestTimeout: 30 * time.Second},
						acceptPattern: func(secrets.Pattern) error { return nil },
					})
					require.NoError(t, err)
					e, err := p.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
					assert.NoError(t, err)
					assert.Equal(t, mockSecretValue, string(e.Value))
					assert.NoError(t, p.close())
					close(doneRuntime)
				}()

				s, err := p.New(mockPlugin, p.WithPluginName("my-plugin"), p.WithConnection(conn))
				require.NoError(t, err)
				assert.NoError(t, s.Run(context.Background()))
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
		})
	}
}
