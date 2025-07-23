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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/internal/testhelper"
)

func Test_hijacking(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), "hijack.sock")
	l := newListener(t, socketPath)
	t.Cleanup(func() { l.Close() })

	httpMux := http.NewServeMux()
	acceptor := newHijackAcceptor()
	httpMux.Handle(acceptor.handler())
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
	connServer, err := testhelper.WaitForWithTimeoutV(acceptor.nextHijackedConn())
	require.NoError(t, err)

	assert.NoError(t, writeLine(connHijacked, "ping"))
	assert.Equal(t, "ping", readLine(connServer))
	assert.NoError(t, writeLine(connServer, "pong"))
	assert.Equal(t, "pong", readLine(connHijacked))
	assert.NoError(t, connServer.Close())
	assert.NoError(t, connHijacked.Close())

	// The server should still be up and also be available for normal/non-hijack stuff
	health, err := requestHealthCheck(socketPath)
	assert.NoError(t, err)
	assert.Equal(t, "ok", health)

	assert.NoError(t, server.Close())
	assert.ErrorIs(t, testhelper.WaitForWithTimeout(serverErr), http.ErrServerClosed)
}

type testHijackAcceptor struct {
	h      hijackHandler
	chConn chan net.Conn
}

func newHijackAcceptor() *testHijackAcceptor {
	chConn := make(chan net.Conn)
	h := &hijackHandler{cb: func(conn net.Conn) { chConn <- conn }, ackTimeout: hijackTimeout}
	return &testHijackAcceptor{chConn: chConn, h: *h}
}

func (h *testHijackAcceptor) handler() (string, http.Handler) {
	return hijackPath, &h.h
}

func (h *testHijackAcceptor) nextHijackedConn() <-chan net.Conn {
	return h.chConn
}

func TestHijackify_hijackRequest_timeout(t *testing.T) {
	socket := "test.sock"
	l, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	conn, err := net.Dial("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	_, err = hijackRequest(conn, 100*time.Millisecond)
	assert.ErrorContains(t, err, "i/o timeout")
}

func readLine(conn net.Conn) string {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimRight(line, "\r\n ")
}

func writeLine(conn net.Conn, line string) error {
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
