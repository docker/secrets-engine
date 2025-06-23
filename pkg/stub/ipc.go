package stub

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/containerd/nri/pkg/net/multiplex"
)

type ipcImpl struct {
	mConn    net.Conn
	server   *ipcServer
	teardown func() error
}

type Ipc interface {
	conn() net.Conn
	wait(ctx context.Context) error
	close() error
}

type ipcServer struct {
	done   chan struct{}
	server *http.Server
	err    error
}

func newIpcServer(l net.Listener, handler http.Handler) *ipcServer {
	result := &ipcServer{
		done: make(chan struct{}),
		server: &http.Server{
			Handler: handler,
		},
	}
	go func() {
		err := result.server.Serve(l)
		if !errors.Is(err, http.ErrServerClosed) {
			result.err = err
		}
		close(result.done)
	}()
	return result
}

func NewIPC(sockConn net.Conn, handler http.Handler) (Ipc, error) {
	mux := multiplex.Multiplex(sockConn)
	listener, err := mux.Listen(multiplex.PluginServiceConn)
	if err != nil {
		mux.Close()
		return nil, err
	}
	conn, err := mux.Open(multiplex.RuntimeServiceConn)
	if err != nil {
		mux.Close()
		return nil, fmt.Errorf("failed to multiplex grcp client connection: %w", err)
	}
	server := newIpcServer(listener, handler)
	return &ipcImpl{
		mConn:  conn,
		server: server,
		teardown: sync.OnceValue(func() error {
			err := errors.Join(server.server.Close(), mux.Close())
			<-server.done
			return err
		}),
	}, nil
}

func (i *ipcImpl) conn() net.Conn {
	return i.mConn
}

func (i *ipcImpl) wait(ctx context.Context) error {
	select {
	case <-i.server.done:
		return i.server.err
	case <-ctx.Done():
		return nil
	}
}

func (i *ipcImpl) close() error {
	return i.teardown()
}
