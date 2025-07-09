//go:build windows

package adaptation

import "os/exec"

// TODO
//
//	We should attempt a graceful shutdown of the process here...
//	  - send it SIGINT
//	  - give the it some slack waiting with a timeout
//	  - butcher it with SIGKILL after the timeout
func shutdownCMD(*exec.Cmd, chan struct{}) {
	// cmd.Process.Kill()
	// cmd.Process.Wait()
	// cmd.Process.Release()
	panic("not implemented yet")
}
