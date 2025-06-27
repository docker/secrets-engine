package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/hashicorp/yamux"
)

func NewPluginIPC(sockConn net.Conn, handler http.Handler) (IPC, *http.Client, error) {
	session, err := yamux.Client(sockConn, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating yamux client: %w", err)
	}
	i, c := newMuxedIPC(session, handler)
	return i, c, nil
}

type IPC interface {
	// Wait blocks forever until the server is closed or an error occurs.
	// Cancelling the context will not close the server, but will return nil.
	Wait(ctx context.Context) error
	// Close shuts down the server and closes the multiplexer, and its connection/listener.
	Close() error
}

func NewRuntimeIPC(sockConn net.Conn, handler http.Handler) (IPC, *http.Client, error) {
	session, err := yamux.Server(sockConn, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating yamux server: %w", err)
	}
	i, c := newMuxedIPC(session, handler)
	return i, c, nil
}

type ipcServer struct {
	done   chan struct{}
	server *http.Server
	err    error
}

func newIpcServer(l net.Listener, handler http.Handler, onError func() error) *ipcServer {
	result := &ipcServer{
		done: make(chan struct{}),
		server: &http.Server{
			Handler: handler,
		},
	}
	go func() {
		err := result.server.Serve(l)
		if !errors.Is(err, http.ErrServerClosed) {
			result.err = errors.Join(err, onError())
		}
		close(result.done)
	}()
	return result
}

type ipcImpl struct {
	server   *ipcServer
	teardown func() error
}

func newMuxedIPC(session *yamux.Session, handler http.Handler) (*ipcImpl, *http.Client) {
	server := newIpcServer(session, handler, session.Close)
	return &ipcImpl{
		server: server,
		teardown: sync.OnceValue(func() error {
			err := errors.Join(server.server.Close(), session.Close())
			<-server.done
			return err
		}),
	}, createYamuxedClient(session)
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

func createYamuxedClient(session *yamux.Session) *http.Client {
	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return session.Open()
		},
	}
	return &http.Client{Transport: transport}
}
