//go:build !windows

package engine

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func askProcessToStop(p proc) error {
	return p.Signal(os.Interrupt)
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
