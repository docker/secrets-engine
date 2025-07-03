package adaptation

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"

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

func isSigint(err error) bool {
	if err == nil {
		return false
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
		return ws.Signaled() && ws.Signal() == syscall.SIGINT
	}
	return false
}
