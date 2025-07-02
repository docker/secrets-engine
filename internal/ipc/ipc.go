package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/sirupsen/logrus"
)

const (
	defaultShutdownTimeout = 2 * time.Second
)

type cfg struct {
	shutdownTimeout time.Duration
}

type Option func(*cfg) *cfg

func WithShutdownTimeout(d time.Duration) Option {
	return func(in *cfg) *cfg {
		in.shutdownTimeout = d
		return in
	}
}

func NewPluginIPC(sockConn net.Conn, handler http.Handler, onServerClosed func(error), option ...Option) (io.Closer, *http.Client, error) {
	// TODO: configure yamux logger
	session, err := yamux.Client(sockConn, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating yamux client: %w", err)
	}
	i, c := newMuxedIPC(session, handler, onServerClosed, option...)
	return i, c, nil
}

func NewRuntimeIPC(sockConn net.Conn, handler http.Handler, onServerClosed func(error), option ...Option) (io.Closer, *http.Client, error) {
	// TODO: configure yamux logger
	session, err := yamux.Server(sockConn, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating yamux server: %w", err)
	}
	i, c := newMuxedIPC(session, handler, onServerClosed, option...)
	return i, c, nil
}

type ipcServer struct {
	done   chan struct{}
	server *http.Server
	err    error
}

func newIpcServer(l net.Listener, handler http.Handler, afterClose func(error) error) *ipcServer {
	result := &ipcServer{
		done: make(chan struct{}),
		server: &http.Server{
			Handler: handler,
		},
	}
	go func() {
		err := result.server.Serve(l)
		if errors.Is(err, http.ErrServerClosed) { // not an error, client closed the connection
			err = nil
		}
		result.err = errors.Join(filterBrokenPipe(filterEOF(err)), afterClose(err)) // EOF: only forward to the afterClose handler, but filter out internal forwarding
		close(result.done)
	}()
	return result
}

func filterEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func filterBrokenPipe(err error) error {
	if errors.Is(err, syscall.EPIPE) {
		return nil
	}
	return err
}

type ipcImpl struct {
	server   *ipcServer
	teardown func() error
}

func newMuxedIPC(session *yamux.Session, handler http.Handler, onClose func(error), option ...Option) (*ipcImpl, *http.Client) {
	// Note: Calling session.Close() needs to be done as the very last step as it shuts down all IPC!

	cfg := &cfg{shutdownTimeout: defaultShutdownTimeout}
	for _, o := range option {
		cfg = o(cfg)
	}
	server := newIpcServer(session, handler, func(err error) error {
		if onClose != nil {
			onClose(err)
		}
		return session.Close()
	})
	c := createYamuxedClient(session)
	return &ipcImpl{
		server: server,
		teardown: sync.OnceValue(func() error {
			_ = session.GoAway()
			c.CloseIdleConnections()
			waitForClientToDisconnect(session, cfg.shutdownTimeout)
			err := server.server.Close()
			<-server.done
			return errors.Join(err, server.err)
		}),
	}, c
}

func waitForClientToDisconnect(s *yamux.Session, t time.Duration) {
	timeout := time.After(t)
	for {
		select {
		case <-time.After(50 * time.Millisecond):
		case <-timeout:
			logrus.Debugf("Timeout expired but %d streams still open, shutting down server...", s.NumStreams())
			return
		}
		streams := s.NumStreams()
		// 1 stream is the control stream (todo: verify)
		// TODO: https://github.com/docker/secrets-engine/issues/71
		if streams <= 1 {
			return
		}
	}
}

func (i *ipcImpl) Close() error {
	return i.teardown()
}

func createYamuxedClient(session *yamux.Session) *http.Client {
	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return session.Open()
		},
	}
	return &http.Client{Transport: transport}
}
