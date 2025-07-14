//go:build windows

package engine

import (
	"os/exec"

	"golang.org/x/sys/windows"
)

func askProcessToStop(cmd *exec.Cmd) error {
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid))
}
