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

//go:build windows

package commands

import (
	"os"
	"os/exec"
	"syscall"
)

// On Windows only SIGINT can be sent to another process via os.Process.Signal;
// SIGTERM and SIGHUP are accepted by signal.Notify but cannot be forwarded to
// a child process.
func forwardableSignals() []os.Signal {
	return []os.Signal{syscall.SIGINT}
}

// configureChildProcGroup is a no-op on Windows. Windows has no Unix-style
// process groups; job objects are the rough equivalent but aren't needed for
// the forwarding contract here.
func configureChildProcGroup(_ *exec.Cmd) {}

func signalChild(child *exec.Cmd, sig os.Signal) error {
	return child.Process.Signal(sig)
}

// Windows does not surface a signaled-process state through ProcessState;
// ExitCode() is authoritative for both normal and abnormal termination.
func childExitCode(state *os.ProcessState) int {
	return state.ExitCode()
}
