//go:build !windows

package plugin

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func askProcessToStop(proc *os.Process) error {
	return proc.Signal(os.Interrupt)
}

func isSigint(err error) bool {
	if err == nil {
		return false
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
		return ws.Signaled() && ws.Signal() == os.Interrupt
	}
	return false
}
