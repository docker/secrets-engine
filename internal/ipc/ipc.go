package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/hashicorp/yamux"
)

func NewPluginIPC(sockConn net.Conn, handler http.Handler, onServerClosed func(error)) (io.Closer, *http.Client, error) {
	// TODO: configure yamux logger
	session, err := yamux.Client(sockConn, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating yamux client: %w", err)
	}
	i, c := newMuxedIPC(session, handler, onServerClosed)
	return i, c, nil
}

func NewRuntimeIPC(sockConn net.Conn, handler http.Handler, onServerClosed func(error)) (io.Closer, *http.Client, error) {
	// TODO: configure yamux logger
	session, err := yamux.Server(sockConn, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating yamux server: %w", err)
	}
	i, c := newMuxedIPC(session, handler, onServerClosed)
	return i, c, nil
}

type ipcServer struct {
	done   chan struct{}
	server *http.Server
	err    error
}

func newIpcServer(l net.Listener, handler http.Handler, onClose func(error) error) *ipcServer {
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
		result.err = errors.Join(err, onClose(err))
		close(result.done)
	}()
	return result
}

type ipcImpl struct {
	server   *ipcServer
	teardown func() error
}

func newMuxedIPC(session *yamux.Session, handler http.Handler, onClose func(error)) (*ipcImpl, *http.Client) {
	server := newIpcServer(session, handler, func(err error) error {
		if onClose != nil {
			onClose(err)
		}
		return session.Close()
	})
	return &ipcImpl{
		server: server,
		teardown: sync.OnceValue(func() error {
			err := errors.Join(server.server.Close(), session.Close())
			<-server.done
			return err
		}),
	}, createYamuxedClient(session)
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
