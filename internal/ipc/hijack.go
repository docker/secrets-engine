package ipc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/docker/secrets-engine/internal/logging"
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

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("clearing deadline: %w", err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
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
	cb         func(ctx context.Context, closer io.ReadWriteCloser)
	ackTimeout time.Duration
	logger     logging.Logger
}

func (h *hijackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking connection", http.StatusInternalServerError)
		return
	}

	conn, brw, hijackErr := hj.Hijack()
	if errors.Is(hijackErr, http.ErrNotSupported) {
		h.logger.Errorf("can't switch protocols using non-Hijacker ResponseWriter")
		return
	}

	if hijackErr != nil {
		h.logger.Errorf("Hijack failed on protocol switch: %v", hijackErr)
		return
	}

	defer conn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)

		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			Proto:      r.Proto,
			Header:     w.Header(),
		}
		resp.Header.Set("Connection", "upgrade")
		resp.Header.Set("Upgrade", "tcp")
		if err := resp.Write(brw); err != nil {
			h.logger.Errorf("writing response: %v", err)
			return
		}
		if err := brw.Flush(); err != nil {
			h.logger.Errorf("flushing response: %v", err)
			return
		}

		h.cb(r.Context(), conn)
	}()

	select {
	case <-done:
	case <-r.Context().Done():
	}
}

func NewHijackAcceptor(logger logging.Logger, cb func(context.Context, io.ReadWriteCloser)) (string, http.Handler) {
	return hijackPath, &hijackHandler{logger: logger, cb: cb, ackTimeout: hijackTimeout}
}
