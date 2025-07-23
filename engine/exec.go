package engine

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/sirupsen/logrus"
)

type cmdWrapper interface {
	close() error
	closed() <-chan struct{}
}

type cmdWatchWrapper struct {
	cmd  *exec.Cmd
	err  error
	done chan struct{}
	name string
}

func launchCmdWatched(name string, cmd *exec.Cmd) cmdWrapper {
	result := &cmdWatchWrapper{name: name, cmd: cmd, done: make(chan struct{})}
	go func() {
		err := cmd.Run()
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

func (w *cmdWatchWrapper) closed() <-chan struct{} {
	return w.done
}

func (w *cmdWatchWrapper) close() error {
	select {
	case <-w.done:
		return w.err
	default:
	}
	shutdownCMD(w.name, w.cmd, w.done)
	return w.err
}

func shutdownCMD(name string, cmd *exec.Cmd, done <-chan struct{}) {
	if cmd.Process == nil {
		return
	}
	if err := askProcessToStop(cmd); err != nil {
		logrus.Errorf("sending SIGINT/CTRL_BREAK_EVENT to plugin '%s': %v", name, err)
		kill(cmd)
		return
	}
	select {
	case <-done:
		return
	case <-time.After(pluginShutdownTimeout):
		logrus.Warnf("plugin '%s' did not shut down after timeout", name)
	}
	kill(cmd)
}

func kill(cmd *exec.Cmd) {
	if err := cmd.Process.Kill(); err != nil {
		logrus.Errorf("sending SIGKILL to plugin: %v", err)
	}
}
