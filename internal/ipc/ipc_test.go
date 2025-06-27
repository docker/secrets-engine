package ipc

import (
	"fmt"
	"io"
	"log"
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

func Test_newExternalPlugin(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "ping pong on both sides",
			test: func(t *testing.T) {
				socketPath := filepath.Join(os.TempDir(), "secrets-engine-plugin.sock")
				os.Remove(socketPath)
				require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0755))
				l, err := net.ListenUnix("unix", &net.UnixAddr{
					Name: socketPath,
					Net:  "unix",
				})
				require.NoError(t, err)
				doneRuntime := make(chan struct{})
				donePlugin := make(chan struct{})
				go func() {
					sock, err := l.Accept()
					if err != nil {
						log.Fatalf("plugin accept: %v", err)
					}
					defer sock.Close()

					pluginHandler := http.NewServeMux()
					pluginHandler.HandleFunc(mockPingPath, func(w http.ResponseWriter, _ *http.Request) {
						fmt.Fprint(w, "pong-runtime")
					})
					i, c, err := NewRuntimeIPC(sock, pluginHandler)
					require.NoError(t, err)
					defer i.Close()
					assertCommunicationToServer(t, c, "pong-plugin")
					assertCommunicationToServer(t, c, "pong-plugin") // run at least twice to ensure re-opening connection works

					close(doneRuntime)
					<-donePlugin
				}()

				sock, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
				if err != nil {
					log.Fatalf("dial error: %v", err)
				}
				t.Cleanup(func() { sock.Close() })

				runtimeHandler := http.NewServeMux()
				runtimeHandler.HandleFunc(mockPingPath, func(w http.ResponseWriter, _ *http.Request) {
					fmt.Fprint(w, "pong-plugin")
				})
				i, c, err := NewPluginIPC(sock, runtimeHandler)
				require.NoError(t, err)
				t.Cleanup(func() { i.Close() })

				assertCommunicationToServer(t, c, "pong-runtime")
				assertCommunicationToServer(t, c, "pong-runtime") // run at least twice to ensure re-opening connection works
				close(donePlugin)
				<-doneRuntime
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

func assertCommunicationToServer(t *testing.T, c *http.Client, response string) {
	req, _ := http.NewRequest("GET", "http://unused"+mockPingPath, nil)
	resp, err := c.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, response, string(body))
}
