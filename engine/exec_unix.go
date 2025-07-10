//go:build !windows

package engine

import (
	"os/exec"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	pluginShutdownTimeout = 2 * time.Second
)

func shutdownCMD(cmd *exec.Cmd, done chan struct{}) {
	if cmd.Process == nil {
		return
	}
	defer func() {
		if err := cmd.Process.Release(); err != nil {
			logrus.Errorf("release process err: %v", err)
		}
	}()
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		logrus.Errorf("sending SIGINT to plugin: %v", err)
	} else {
		select {
		case <-done:
			return
		case <-time.After(pluginShutdownTimeout):
		}
	}
	if err := cmd.Process.Kill(); err != nil {
		logrus.Errorf("sending SIGKILL to plugin: %v", err)
	}
	<-done // wait before calling Release()
}
