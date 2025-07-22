package ipc

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	mockPingPath = "/ping"
)

func Test_ipc(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "ping pong on both sides",
			test: func(t *testing.T) {
				socketPath := filepath.Join(os.TempDir(), "secrets-engine-plugin.sock")
				l := newListener(t, socketPath)
				doneRuntime := make(chan struct{})
				donePlugin := make(chan struct{})
				go func() {
					sock, err := l.Accept()
					require.NoError(t, err)
					defer sock.Close()

					i, c, err := NewRuntimeIPC(sock, newPingPongHandler("runtime"), nil)
					require.NoError(t, err)
					defer i.Close()
					assertCommunicationToServer(t, c, "pong-plugin")
					assertCommunicationToServer(t, c, "pong-plugin") // run at least twice to ensure re-opening connection works

					close(doneRuntime)
					<-donePlugin
				}()

				sock, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
				require.NoError(t, err)
				t.Cleanup(func() { sock.Close() })

				i, c, err := NewPluginIPC(sock, newPingPongHandler("plugin"), nil)
				require.NoError(t, err)
				t.Cleanup(func() { i.Close() })

				assertCommunicationToServer(t, c, "pong-runtime")
				assertCommunicationToServer(t, c, "pong-runtime") // run at least twice to ensure re-opening connection works
				close(donePlugin)
				<-doneRuntime
			},
		},
		{
			name: "stopping the plugin results in EOF on runtime side",
			test: func(t *testing.T) {
				socketPath := filepath.Join(os.TempDir(), "secrets-engine-plugin.sock")
				listener := newListener(t, socketPath)

				doneRuntime := make(chan struct{})
				donePlugin := make(chan struct{})
				go func() {
					conn, err := listener.Accept()
					require.NoError(t, err)

					i, _, err := NewRuntimeIPC(conn, newPingPongHandler("runtime"), func(err error) {
						assert.ErrorIs(t, err, io.EOF)
						close(donePlugin)
					})
					require.NoError(t, err)
					<-donePlugin
					assert.NoError(t, i.Close())
					assert.ErrorContains(t, conn.Close(), "use of closed network connection")
					close(doneRuntime)
				}()

				sock, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
				require.NoError(t, err)

				i, c, err := NewPluginIPC(sock, newPingPongHandler("plugin"), func(err error) {
					assert.NoError(t, err)
					assert.ErrorContains(t, sock.Close(), "use of closed network connection")
				})
				require.NoError(t, err)

				assertCommunicationToServer(t, c, "pong-runtime")
				assert.NoError(t, i.Close())

				<-doneRuntime
				assert.NoError(t, listener.Close())
			},
		},
		{
			name: "stopping the runtime results in EOF on plugin side",
			test: func(t *testing.T) {
				socketPath := filepath.Join(os.TempDir(), "secrets-engine-plugin.sock")
				listener := newListener(t, socketPath)

				runtimeDown := make(chan struct{})
				pluginReady := make(chan struct{})
				pluginDown := make(chan struct{})
				go func() {
					sock, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
					require.NoError(t, err)

					done := make(chan struct{})
					i, c, err := NewPluginIPC(sock, newPingPongHandler("plugin"), func(err error) {
						assert.ErrorIs(t, err, io.EOF)
						assert.ErrorContains(t, sock.Close(), "use of closed network connection")
						close(done)
					})
					require.NoError(t, err)
					assertCommunicationToServer(t, c, "pong-runtime")
					close(pluginReady)
					<-done
					assert.NoError(t, i.Close())
					close(pluginDown)
				}()

				conn, err := listener.Accept()
				require.NoError(t, err)

				i, _, err := NewRuntimeIPC(conn, newPingPongHandler("runtime"), func(err error) {
					assert.NoError(t, err)
					assert.ErrorContains(t, conn.Close(), "use of closed network connection")
					close(runtimeDown)
				})
				require.NoError(t, err)
				<-pluginReady
				assert.NoError(t, i.Close())
				<-pluginDown
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

func newListener(t *testing.T, socketPath string) net.Listener {
	t.Helper()
	l, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	return l
}

func newPingPongHandler(suffix string) http.Handler {
	runtimeHandler := http.NewServeMux()
	runtimeHandler.HandleFunc(mockPingPath, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "pong-"+suffix)
	})
	return runtimeHandler
}

func assertCommunicationToServer(t *testing.T, c *http.Client, response string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://unused"+mockPingPath, nil)
	resp, err := c.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, response, string(body))
}
