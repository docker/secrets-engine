// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !windows

package commands

import (
	"os"
	"os/exec"
	"syscall"
)

func forwardableSignals() []os.Signal {
	return []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}
}

// configureChildProcGroup puts the child into its own process group. Without
// this, the TTY driver delivers terminal-generated signals (Ctrl-C → SIGINT,
// Ctrl-\ → SIGQUIT) to every process in the parent's foreground group,
// double-delivering them: once by the TTY directly and once by our forwarder.
// Isolating the child means the forwarder becomes the sole dispatcher.
func configureChildProcGroup(child *exec.Cmd) {
	if child.SysProcAttr == nil {
		child.SysProcAttr = &syscall.SysProcAttr{}
	}
	child.SysProcAttr.Setpgid = true
}

// signalChild delivers sig to the child's whole process group so that any
// subprocesses the child spawned also receive the signal (e.g. `bash -c
// "sleep 100"` should interrupt the sleep, not just the shell).
func signalChild(child *exec.Cmd, sig os.Signal) error {
	sysSig, ok := sig.(syscall.Signal)
	if !ok {
		return child.Process.Signal(sig)
	}
	return syscall.Kill(-child.Process.Pid, sysSig)
}

func childExitCode(state *os.ProcessState) int {
	if state.Exited() {
		return state.ExitCode()
	}
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return state.ExitCode()
}
