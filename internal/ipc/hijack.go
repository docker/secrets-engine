package ipc

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

const hijackPath = "/hijack"

// CloseWriter is the interface for a Conn that can half-close its write side.
type CloseWriter interface {
	CloseWrite() error
}

// hijackedConn wraps the raw net.Conn but punts Read through
// the bufio.Reader that has already consumed the HTTP headers.
type hijackedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (hc *hijackedConn) Read(p []byte) (int, error) {
	return hc.reader.Read(p)
}

// hijackedConnCloseWriter also implements CloseWrite if the underlying conn does.
type hijackedConnCloseWriter struct {
	*hijackedConn
}

func (hcw *hijackedConnCloseWriter) CloseWrite() error {
	if cw, ok := hcw.Conn.(CloseWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Hijackify to be used in conjunction with HijackAcceptor.
// Tells the server to perform hijack operation on the connection which means the server
// will retrieve the underlying tcp connection and hand it over / no longer serves requests to it.
// -> we can use it as a long-running server-client connection and re-purpose it to run our IPC/yamux stack on top.
func Hijackify(conn net.Conn) (net.Conn, error) {
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

	req, err := http.NewRequest("GET", "http://secrets-engine.localhost"+hijackPath, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("making hijack request: %s", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("upgrading: %s", resp.Status)
	}

	if br.Buffered() > 0 {
		if _, ok := conn.(CloseWriter); ok {
			conn = &hijackedConnCloseWriter{&hijackedConn{conn, br}}
		} else {
			conn = &hijackedConn{conn, br}
		}
	} else {
		br.Reset(nil)
	}

	return conn, nil
}

type hijackHandler struct {
	chConn chan net.Conn
}

func (h *hijackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking connection", http.StatusInternalServerError)
		return
	}

	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "server does not support flushing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Connection", "upgrade")
	w.Header().Set("Upgrade", "tcp")
	w.WriteHeader(http.StatusSwitchingProtocols)
	f.Flush()

	conn, _, err := hj.Hijack()
	if err != nil {
		logrus.Errorf("hijack error: %v", err)
		return
	}

	h.chConn <- conn
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
	return &HijackAcceptor{hijackHandler{chConn: make(chan net.Conn)}}
}
