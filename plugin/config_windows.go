//go:build windows

package plugin

import (
	"io"
	"os"

	"github.com/docker/secrets-engine/internal/ipc"
)

func connectionFromFileDescriptor(cfg ipc.PluginConfigFromEngine) (io.ReadWriteCloser, error) {
	return &ipc.PipeConn{
		R: os.NewFile(uintptr(cfg.R), "child→parent"),
		W: os.NewFile(uintptr(cfg.W), "parent→child"),
	}, nil
}
