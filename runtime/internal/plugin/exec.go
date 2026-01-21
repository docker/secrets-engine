package plugin

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

type execProcess interface {
	start() error
	wait() error
	kill() error
	sigint() error
}

// Concurrency safe wrapper around exec.Cmd:
// Kill() and Sigint() can safely be called from other go routines.
type process struct {
	cmd     *exec.Cmd
	process *os.Process
	m       sync.Mutex
}

func (p *process) start() error {
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

func (p *process) wait() error {
	return p.cmd.Wait()
}

func (p *process) kill() error {
	p.m.Lock()
	defer p.m.Unlock()
	if p.process == nil {
		return nil
	}
	return p.process.Kill()
}

func (p *process) setProcess(proc *os.Process) {
	p.m.Lock()
	defer p.m.Unlock()
	p.process = proc
}

func (p *process) sigint() error {
	p.m.Lock()
	defer p.m.Unlock()
	if p.process == nil {
		return nil
	}
	return askProcessToStop(p.process)
}

type Watcher interface {
	io.Closer
	Closed() <-chan struct{}
	Kill() error
}

type watcher struct {
	process         execProcess
	err             error
	done            chan struct{}
	name            string
	shutdownTimeout time.Duration
	logger          logging.Logger
}

func NewProcess(cmd *exec.Cmd) execProcess {
	return &process{cmd: cmd}
}

func WatchProcess(logger logging.Logger, name string, p execProcess, timeout time.Duration) Watcher {
	w := &watcher{
		process:         p,
		logger:          logger,
		name:            name,
		done:            make(chan struct{}),
		shutdownTimeout: timeout,
	}
	if err := w.process.start(); err != nil {
		w.err = err
		close(w.done)
		return w
	}
	go func() {
		err := w.process.wait()
		// On linux, if the process doesn't listen to SIGINT / explicitly handles it, cmd.Wait() returns an error.
		// It's not an error for us, but logging it could help giving feedback to improve the plugin implementation.
		if isSigint(err) {
			logger.Printf("Plugin %s returned sigint error. Is SIGINT signal being properly handled?", name)
			err = nil
		}
		if err != nil {
			err = fmt.Errorf("plugin %s crashed: %w", name, err)
		}
		w.err = err
		close(w.done)
	}()
	return w
}

func (w *watcher) Closed() <-chan struct{} {
	return w.done
}

func (w *watcher) Close() error {
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

func (w *watcher) Kill() error {
	if err := w.process.kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		w.logger.Errorf("sending SIGKILL to plugin: %v", err)
		return err
	}
	return nil
}

// Assures cmd gets shut down (gracefully). However, cmd.Run() could still
// terminating on its own for any kind of reason.
// -> filter out os.ErrProcessDone
func (w *watcher) shutdownCMD() {
	if err := w.process.sigint(); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return
		}
		w.logger.Errorf("sending SIGINT/CTRL_BREAK_EVENT to plugin '%s': %v", w.name, err)
		_ = w.Kill()
		return
	}
	select {
	case <-w.done:
		return
	case <-time.After(w.shutdownTimeout):
		w.logger.Warnf("plugin '%s' did not shut down after timeout", w.name)
	}
	_ = w.Kill()
}

type shutdownHelperImpl struct {
	m                sync.Mutex
	alreadyTriggered bool
	close            func() error
	lastErr          error
	done             chan struct{}
}

type ShutdownHelper interface {
	Shutdown(err error) error
	Closed() <-chan struct{}
}

func NewShutdownHelper(c func() error) ShutdownHelper {
	return &shutdownHelperImpl{close: c, done: make(chan struct{})}
}

func (r *shutdownHelperImpl) Shutdown(err error) error {
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

func (r *shutdownHelperImpl) Closed() <-chan struct{} {
	return r.done
}
