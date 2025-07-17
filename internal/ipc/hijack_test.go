package ipc

import (
	"bufio"
	"context"
	"errors"
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
)

func Test_hijacking(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), "hijack.sock")
	l := newListener(t, socketPath)
	t.Cleanup(func() { l.Close() })

	httpMux := http.NewServeMux()
	acceptor := NewHijackAcceptor()
	httpMux.Handle(acceptor.Handler())
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	serverErr := make(chan error, 1)
	server := &http.Server{Handler: httpMux}
	go func() {
		serverErr <- server.Serve(l)
	}()
	connUnhijacked, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { connUnhijacked.Close() })
	connHijacked, err := Hijackify(connUnhijacked)
	require.NoError(t, err)
	connServer, err := getServerConnWithTimeout(acceptor.NextHijackedConn(), 2*time.Second)
	require.NoError(t, err)

	assert.NoError(t, writeLine(connHijacked, "ping"))
	assert.Equal(t, "ping", readLine(connServer))
	assert.NoError(t, writeLine(connServer, "pong"))
	assert.Equal(t, "pong", readLine(connHijacked))
	assert.NoError(t, connServer.Close())
	assert.NoError(t, connHijacked.Close())
	assert.ErrorContains(t, connUnhijacked.Close(), "use of closed network connection")

	// The server should still be up and also be available for normal/non-hijack stuff
	health, err := requestHealthCheck(socketPath)
	assert.NoError(t, err)
	assert.Equal(t, "ok", health)

	assert.NoError(t, server.Close())
	assert.ErrorIs(t, waitForErrorWithTimeout(serverErr), http.ErrServerClosed)
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

func waitForErrorWithTimeout(chErr <-chan error) error {
	select {
	case err := <-chErr:
		return err
	case <-time.After(2 * time.Second):
		return errors.New("timeout")
	}
}

func getServerConnWithTimeout(chConn <-chan net.Conn, timeout time.Duration) (net.Conn, error) {
	select {
	case conn := <-chConn:
		return conn, nil
	case <-time.After(timeout):
		return nil, errors.New("timeout")
	}
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
