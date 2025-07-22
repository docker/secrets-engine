package ipc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	hijackPath    = "/hijack"
	hijackTimeout = 2 * time.Second
)

// Hijackify to be used in conjunction with HijackAcceptor.
// Tells the server to perform hijack operation on the connection which means the server
// will retrieve the underlying tcp connection and hand it over / no longer serves requests to it.
// -> we can use it as a long-running server-client connection and re-purpose it to run our IPC/yamux stack on top.
func Hijackify(conn net.Conn, timeout time.Duration) (net.Conn, error) {
	// When we set up a TCP connection for hijack, there could be long periods
	// of inactivity (a long running command with no output) that in certain
	// network setups may cause ECONNTIMEOUT, leaving the client in an unknown
	// state. Setting TCP KeepAlive on the socket connection will prohibit
	// ECONNTIMEOUT unless the socket connection truly is broken
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			logrus.Errorf("failed to set keep alive flag: %s", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			logrus.Errorf("failed to set keep alive period: %s", err)
		}
	}

	hijackedConn, err := hijackRequest(conn, timeout)
	if err != nil {
		return nil, err
	}
	return hijackedConn, nil
}

func hijackRequest(conn net.Conn, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://secrets-engine.localhost"+hijackPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "tcp")

	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("making hijack request: %s", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("clearing deadline: %w", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		var respBody []byte
		respBody, _ = io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	return &hijackedConn{conn, br}, nil
}

var _ CloseWriter = &hijackedConn{}

type hijackedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *hijackedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *hijackedConn) Close() error {
	return c.Conn.Close()
}

func (c *hijackedConn) CloseWrite() error {
	// If the underlying connection implements CloseWrite, we forward it.
	if cw, ok := c.Conn.(CloseWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

type CloseWriter interface {
	CloseWrite() error
}

type hijackHandler struct {
	cb         func(net.Conn)
	ackTimeout time.Duration
}

func (h *hijackHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking connection", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Connection", "upgrade")
	w.Header().Set("Upgrade", "tcp")
	w.WriteHeader(http.StatusSwitchingProtocols) // 1xx headers are sent immediately -> no flush needed

	conn, _, err := hj.Hijack()
	if err != nil {
		logrus.Errorf("hijack error: %v", err)
		return
	}

	h.cb(conn)
}

func NewHijackAcceptor(cb func(conn net.Conn)) (string, http.Handler) {
	return hijackPath, &hijackHandler{cb: cb, ackTimeout: hijackTimeout}
}
