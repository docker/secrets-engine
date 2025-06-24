package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/containerd/nri/pkg/net/multiplex"
)

type PluginIPC interface {
	// Conn returns a connection that can be used to reach the runtime server on the other end of
	// the multiplexed connection (this is not the original net.Conn, but a multiplexed connection!).
	Conn() net.Conn
	// Wait blocks forever until the server is closed or an error occurs.
	// Cancelling the context will not close the server, but will return nil.
	Wait(ctx context.Context) error
	// Close shuts down the server and closes the multiplexer, and its connection/listener.
	Close() error
}

func NewPluginIPC(sockConn net.Conn, handler http.Handler) (PluginIPC, error) {
	return newMuxedIPC(sockConn, handler, multiplex.PluginServiceConn, multiplex.RuntimeServiceConn)
}

type RuntimeIPC interface {
	// Conn returns a connection that can be used to reach the server running in the plugin on the other end of
	// the multiplexed connection (this is not the original net.Conn, but a multiplexed connection!).
	Conn() net.Conn
	// Wait blocks forever until the server is closed or an error occurs.
	// Cancelling the context will not close the server, but will return nil.
	Wait(ctx context.Context) error
	// Close shuts down the server and closes the multiplexer, and its connection/listener.
	Close() error
	// Unblock unblocks the multiplexed connection, allowing it to read from the socket.
	Unblock()
}

func NewRuntimeIPC(sockConn net.Conn, handler http.Handler) (RuntimeIPC, error) {
	return newMuxedIPC(sockConn, handler, multiplex.RuntimeServiceConn, multiplex.PluginServiceConn, multiplex.WithBlockedRead())
}

type ipcServer struct {
	done   chan struct{}
	server *http.Server
	err    error
}

func newIpcServer(l net.Listener, handler http.Handler, onError func()) *ipcServer {
	result := &ipcServer{
		done: make(chan struct{}),
		server: &http.Server{
			Handler: handler,
		},
	}
	go func() {
		err := result.server.Serve(l)
		if !errors.Is(err, http.ErrServerClosed) {
			onError()
			result.err = err
		}
		close(result.done)
	}()
	return result
}

type ipcImpl struct {
	mConn    net.Conn
	server   *ipcServer
	teardown func() error
	unblock  func()
}

func newMuxedIPC(sockConn net.Conn, handler http.Handler, listenerID, connID multiplex.ConnID, options ...multiplex.Option) (*ipcImpl, error) {
	mux := multiplex.Multiplex(sockConn, options...)
	listener, err := mux.Listen(listenerID)
	if err != nil {
		mux.Close()
		return nil, err
	}
	conn, err := mux.Open(connID)
	if err != nil {
		mux.Close()
		return nil, fmt.Errorf("failed to multiplex grcp client connection: %w", err)
	}
	server := newIpcServer(listener, handler, func() { mux.Close() })
	return &ipcImpl{
		mConn:  conn,
		server: server,
		teardown: sync.OnceValue(func() error {
			err := errors.Join(server.server.Close(), mux.Close())
			<-server.done
			return err
		}),
		unblock: mux.Unblock,
	}, nil
}

func (i *ipcImpl) Conn() net.Conn {
	return i.mConn
}

func (i *ipcImpl) Wait(ctx context.Context) error {
	select {
	case <-i.server.done:
		return i.server.err
	case <-ctx.Done():
		return nil
	}
}

func (i *ipcImpl) Close() error {
	return i.teardown()
}

func (i *ipcImpl) Unblock() {
	i.unblock()
}
