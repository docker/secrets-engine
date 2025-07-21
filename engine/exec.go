package engine

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/sirupsen/logrus"
)

type cmdWatchWrapper struct {
	cmd  *exec.Cmd
	err  error
	done chan struct{}
}

func newCmdWatchWrapper(name string, cmd *exec.Cmd) *cmdWatchWrapper {
	result := &cmdWatchWrapper{cmd: cmd, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		// On linux, if the process doesn't listen to SIGINT / explicitly handles it, cmd.Wait() returns an error.
		// It's not an error for us, but logging it could help giving feedback to improve the plugin implementation.
		if isSigint(err) {
			logrus.Infof("Plugin %s returned sigint error. Is SIGINT signal being properly handled?", name)
			err = nil
		}
		if err != nil {
			err = fmt.Errorf("plugin %s crashed: %w", name, err)
		}
		result.err = err
		close(result.done)
	}()
	return result
}

func (w *cmdWatchWrapper) close() error {
	select {
	case <-w.done:
		return w.err
	default:
	}
	shutdownCMD(w.cmd, w.done)
	return w.err
}

func shutdownCMD(cmd *exec.Cmd, done chan struct{}) {
	if cmd.Process == nil {
		return
	}
	if err := askProcessToStop(cmd); err != nil {
		logrus.Errorf("sending SIGINT/CTRL_BREAK_EVENT to plugin: %v", err)
		kill(cmd)
		return
	}
	select {
	case <-done:
		return
	case <-time.After(pluginShutdownTimeout):
	}
	kill(cmd)
}

func kill(cmd *exec.Cmd) {
	if err := cmd.Process.Kill(); err != nil {
		logrus.Errorf("sending SIGKILL to plugin: %v", err)
	}
}
