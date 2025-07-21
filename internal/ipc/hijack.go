package ipc

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	hijackPath = "/hijack"
	ackTimeout = 2 * time.Second
)

// Hijackify to be used in conjunction with HijackAcceptor.
// Tells the server to perform hijack operation on the connection which means the server
// will retrieve the underlying tcp connection and hand it over / no longer serves requests to it.
// -> we can use it as a long-running server-client connection and re-purpose it to run our IPC/yamux stack on top.
func Hijackify(conn net.Conn) error {
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

	if err := hijackRequest(conn); err != nil {
		return err
	}

	if err := writeAckWithTimeout(conn, ackTimeout); err != nil {
		return err
	}

	return nil
}

func hijackRequest(conn net.Conn) error {
	req, err := http.NewRequest("GET", "http://secrets-engine.localhost"+hijackPath, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "tcp")

	if err := req.Write(conn); err != nil {
		return fmt.Errorf("making hijack request: %s", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		var respBody []byte
		respBody, _ = io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func writeAckWithTimeout(conn net.Conn, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("clearing deadline: %w", err)
	}
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()

	// We tell the server that we have fully read the response by sending a single byte ack.
	// This prevents the server from starting to send traffic while we are still reading the previous HTTP response.
	if _, err := conn.Write([]byte{0}); err != nil {
		return fmt.Errorf("write ack: %w", err)
	}
	return nil
}

type hijackHandler struct {
	chConn     chan net.Conn
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

	if err := readAckWithTimeout(conn, h.ackTimeout); err != nil {
		conn.Close()
		logrus.Errorf("waiting for ack: %v", err)
		return
	}

	h.chConn <- conn
}

func readAckWithTimeout(conn net.Conn, timeout time.Duration) error {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("clearing deadline: %w", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	// The client confirms it has fully read the hijack response and is ready to serve whatever might come next.
	// This prevents race conditions where we start using the connection on the server for something else already
	// before the response has been fully read, which can mix traffic.
	ack := make([]byte, 1)
	if _, err := conn.Read(ack); err != nil {
		return fmt.Errorf("reading ack: %w", err)
	}
	return nil
}

type HijackAcceptor struct {
	h hijackHandler
}

func (h *HijackAcceptor) Handler() (string, http.Handler) {
	return hijackPath, &h.h
}

func (h *HijackAcceptor) NextHijackedConn() <-chan net.Conn {
	return h.h.chConn
}

func NewHijackAcceptor() *HijackAcceptor {
	return &HijackAcceptor{hijackHandler{chConn: make(chan net.Conn), ackTimeout: ackTimeout}}
}
