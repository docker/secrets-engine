package engine

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/docker/secrets-engine/x/logging"
)

type proc interface {
	start() error
	wait() error
	kill() error
	sigint() error
}

// Concurrency safe wrapper around exec.Cmd:
// Kill() and Sigint() can safely be called from other go routines.
type procImpl struct {
	cmd     *exec.Cmd
	process *os.Process
	m       sync.Mutex
}

func (p *procImpl) start() error {
	if err := p.cmd.Start(); err != nil {
		return err
	}
	// We need to create another instance of os.Process as cmd.Process is not concurrency safe
	// -> Calling cmd.Process.Kill from another Go routine while cmd.Wait is pending creates a data race
	proc, err := os.FindProcess(p.cmd.Process.Pid)
	if err != nil {
		return err
	}
	p.setProcess(proc)
	return nil
}

func (p *procImpl) wait() error {
	return p.cmd.Wait()
}

func (p *procImpl) kill() error {
	p.m.Lock()
	defer p.m.Unlock()
	if p.process == nil {
		return nil
	}
	return p.process.Kill()
}

func (p *procImpl) setProcess(proc *os.Process) {
	p.m.Lock()
	defer p.m.Unlock()
	p.process = proc
}

func (p *procImpl) sigint() error {
	p.m.Lock()
	defer p.m.Unlock()
	if p.process == nil {
		return nil
	}
	return askProcessToStop(p.process)
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
	logger          logging.Logger
}

func launchCmdWatched(logger logging.Logger, name string, p proc, timeout time.Duration) procWrapper {
	result := &cmdWatchWrapper{logger: logger, name: name, p: p, done: make(chan struct{}), shutdownTimeout: timeout}
	if err := p.start(); err != nil {
		result.err = err
		close(result.done)
		return result
	}
	go func() {
		err := p.wait()
		// On linux, if the process doesn't listen to SIGINT / explicitly handles it, cmd.Wait() returns an error.
		// It's not an error for us, but logging it could help giving feedback to improve the plugin implementation.
		if isSigint(err) {
			logger.Printf("Plugin %s returned sigint error. Is SIGINT signal being properly handled?", name)
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
	w.shutdownCMD()
	select {
	case <-w.done:
		return w.err
	case <-time.After(w.shutdownTimeout):
		return fmt.Errorf("timeout killing plugin '%s'", w.name)
	}
}

func (w *cmdWatchWrapper) kill() {
	if err := w.p.kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		w.logger.Errorf("sending SIGKILL to plugin: %v", err)
	}
}

// Assures cmd gets shut down (gracefully). However, cmd.Run() could still
// terminating on its own for any kind of reason.
// -> filter out os.ErrProcessDone
func (w *cmdWatchWrapper) shutdownCMD() {
	if err := w.p.sigint(); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return
		}
		w.logger.Errorf("sending SIGINT/CTRL_BREAK_EVENT to plugin '%s': %v", w.name, err)
		w.kill()
		return
	}
	select {
	case <-w.done:
		return
	case <-time.After(w.shutdownTimeout):
		w.logger.Warnf("plugin '%s' did not shut down after timeout", w.name)
	}
	w.kill()
}

type shutdownHelperImpl struct {
	m                sync.Mutex
	alreadyTriggered bool
	close            func() error
	lastErr          error
	done             chan struct{}
}

type shutdownHelper interface {
	shutdown(err error) error
	closed() <-chan struct{}
}

func newShutdownHelper(c func() error) shutdownHelper {
	return &shutdownHelperImpl{close: c, done: make(chan struct{})}
}

func (r *shutdownHelperImpl) shutdown(err error) error {
	r.m.Lock()
	defer r.m.Unlock()
	if r.alreadyTriggered {
		return r.lastErr
	}
	defer close(r.done)
	r.alreadyTriggered = true
	r.lastErr = errors.Join(err, r.close())
	return r.lastErr
}

func (r *shutdownHelperImpl) closed() <-chan struct{} {
	return r.done
}
