//go:build !windows

package engine

import (
	"os"
	"os/exec"
)

func askProcessToStop(cmd *exec.Cmd) error {
	return cmd.Process.Signal(os.Interrupt)
}
