//go:build windows

package engine

import (
	"errors"
	"os/exec"

	"golang.org/x/sys/windows"
)

func askProcessToStop(p proc) error {
	pid := p.PID()
	if pid <= 0 {
		return nil
	}
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(pid))
}

func isSigint(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	// on Windows 0xC000013A means STATUS_CONTROL_C_EXIT
	return exitErr.ExitCode() == 0xC000013A
}
