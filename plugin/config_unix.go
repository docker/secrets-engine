//go:build !windows

package plugin

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/docker/secrets-engine/internal/ipc"
)

func connectionFromFileDescriptor(cfg ipc.PluginConfigFromEngine) (io.ReadWriteCloser, error) {
	f := os.NewFile(uintptr(cfg.Fd), "fd #"+strconv.Itoa(cfg.Fd))
	if f == nil {
		return nil, fmt.Errorf("failed to open FD %d", cfg.Fd)
	}
	defer f.Close()
	conn, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create net.Conn for fd #%d: %w", cfg.Fd, err)
	}
	return conn, nil
}
