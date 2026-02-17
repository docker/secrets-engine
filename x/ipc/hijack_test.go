// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipc

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/x/testhelper"
)

func Test_hijacking(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), "hijack.sock")
	l := newListener(t, socketPath)
	t.Cleanup(func() { l.Close() })

	httpMux := http.NewServeMux()
	ch := make(chan io.ReadWriteCloser)
	wait := make(chan struct{})
	once := sync.OnceFunc(func() { close(wait) })
	defer once()
	httpMux.Handle(NewHijackAcceptor(testhelper.TestLogger(t), func(_ context.Context, closer io.ReadWriteCloser) {
		ch <- closer
		<-wait
	}))
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	serverErr := make(chan error, 1)
	server := &http.Server{Handler: httpMux}
	go func() {
		serverErr <- server.Serve(l)
	}()
	connClient, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { connClient.Close() })
	connHijacked, err := Hijackify(connClient, hijackTimeout)
	require.NoError(t, err)
	connServer, err := testhelper.WaitForWithTimeoutV(ch)
	require.NoError(t, err)

	assert.NoError(t, writeLine(connHijacked, "ping"))
	assert.Equal(t, "ping", readLine(connServer))
	assert.NoError(t, writeLine(connServer, "pong"))
	assert.Equal(t, "pong", readLine(connHijacked))
	assert.NoError(t, connServer.Close())
	assert.NoError(t, connHijacked.Close())
	once()

	// The server should still be up and also be available for normal/non-hijack stuff
	health, err := requestHealthCheck(socketPath)
	assert.NoError(t, err)
	assert.Equal(t, "ok", health)

	assert.NoError(t, server.Close())
	assert.ErrorIs(t, testhelper.WaitForErrorWithTimeout(serverErr), http.ErrServerClosed)
}

func TestHijackify_hijackRequest_timeout(t *testing.T) {
	socket := testhelper.RandomShortSocketName()
	l, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	conn, err := net.Dial("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	_, err = Hijackify(conn, 100*time.Millisecond)
	assert.ErrorContains(t, err, "i/o timeout")
}

func readLine(conn io.ReadWriteCloser) string {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimRight(line, "\r\n ")
}

func writeLine(conn io.ReadWriteCloser, line string) error {
	_, err := conn.Write([]byte(line + "\r\n"))
	return err
}

func requestHealthCheck(socketPath string) (string, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", err
	}
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return conn, nil
			},
		},
	}
	req, _ := http.NewRequest("GET", "http://unused/health", nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(body), nil
}
