package engine

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/sirupsen/logrus"
)

type proc interface {
	Run() error
	Signal(sig os.Signal) error
	Kill() error
	PID() int
}

type procImpl struct {
	cmd *exec.Cmd
}

func (p procImpl) Run() error {
	return p.cmd.Run()
}

func (p procImpl) Signal(sig os.Signal) error {
	if p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Signal(sig)
}

func (p procImpl) Kill() error {
	if p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Kill()
}

func (p procImpl) PID() int {
	if p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

func fromCmd(cmd *exec.Cmd) proc {
	return &procImpl{cmd: cmd}
}

type procWrapper interface {
	io.Closer
	Closed() <-chan struct{}
}

type cmdWatchWrapper struct {
	p               proc
	err             error
	done            chan struct{}
	name            string
	shutdownTimeout time.Duration
}

func launchCmdWatched(name string, p proc, timeout time.Duration) procWrapper {
	result := &cmdWatchWrapper{name: name, p: p, done: make(chan struct{}), shutdownTimeout: timeout}
	go func() {
		err := p.Run()
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

func (w *cmdWatchWrapper) Closed() <-chan struct{} {
	return w.done
}

func (w *cmdWatchWrapper) Close() error {
	select {
	case <-w.done:
		return w.err
	default:
	}
	shutdownCMD(w.name, w.p, w.done, w.shutdownTimeout)
	select {
	case <-w.done:
		return w.err
	case <-time.After(w.shutdownTimeout):
		return fmt.Errorf("timeout killing plugin '%s'", w.name)
	}
}

// Assures cmd gets shut down (gracefully). However, cmd.Run() could still
// terminating on its own for any kind of reason.
// -> filter out os.ErrProcessDone
func shutdownCMD(name string, p proc, done <-chan struct{}, timeout time.Duration) {
	if err := askProcessToStop(p); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return
		}
		logrus.Errorf("sending SIGINT/CTRL_BREAK_EVENT to plugin '%s': %v", name, err)
		kill(p)
		return
	}
	select {
	case <-done:
		return
	case <-time.After(timeout):
		logrus.Warnf("plugin '%s' did not shut down after timeout", name)
	}
	kill(p)
}

func kill(p proc) {
	if err := p.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		logrus.Errorf("sending SIGKILL to plugin: %v", err)
	}
}
