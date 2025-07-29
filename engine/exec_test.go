package engine

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/docker/secrets-engine/internal/testhelper"
)

type mockCmd struct {
	killReceived   chan struct{}
	killDone       chan error
	signalReceived chan struct{}
	signalDone     chan error
	runReceived    chan struct{}
	runDone        chan error
}

func (m *mockCmd) Run() error {
	close(m.runReceived)
	err := <-m.runDone
	return err
}

func (m *mockCmd) Kill() error {
	close(m.killReceived)
	err := <-m.killDone
	return err
}

func (m *mockCmd) Signal(os.Signal) error {
	close(m.signalReceived)
	err := <-m.signalDone
	return err
}

func (m *mockCmd) PID() int {
	close(m.signalReceived)
	<-m.signalDone
	return -1
}

func Test_launchCmdWatched(t *testing.T) {
	t.Parallel()
	t.Run("Close races against cmd terminating on its own", func(t *testing.T) {
		runErr := errors.New("run error")
		cmd := &mockCmd{
			signalReceived: make(chan struct{}),
			signalDone:     make(chan error, 1),
			runReceived:    make(chan struct{}),
			runDone:        make(chan error, 1),
		}
		wrapper := launchCmdWatched(testLogger(t), "foo", cmd, 5*time.Second)
		assert.False(t, isClosed(wrapper.Closed()))
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(cmd.runReceived))
		errClose := make(chan error)
		go func() {
			errClose <- wrapper.Close()
		}()
		assert.False(t, isClosed(wrapper.Closed()))
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(cmd.signalReceived))
		cmd.runDone <- runErr
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.True(c, isClosed(wrapper.Closed()))
		}, 2*time.Second, 100*time.Millisecond)
		assert.False(t, isClosed(errClose))
		cmd.signalDone <- os.ErrProcessDone
		assert.Error(t, <-errClose)
	})
	t.Run("Close returns run error when cmd terminates on its own (no racing)", func(t *testing.T) {
		runErr := errors.New("run error")
		cmd := &mockCmd{
			runReceived: make(chan struct{}),
			runDone:     make(chan error, 1),
		}
		wrapper := launchCmdWatched(testLogger(t), "foo", cmd, 5*time.Second)
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(cmd.runReceived))
		cmd.runDone <- runErr
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.True(c, isClosed(wrapper.Closed()))
		}, 2*time.Second, 100*time.Millisecond)
		assert.ErrorIs(t, wrapper.Close(), runErr)
	})
	t.Run("process is shutdown gracefully and eventually we timeout", func(t *testing.T) {
		cmd := &mockCmd{
			runReceived:    make(chan struct{}),
			runDone:        make(chan error, 1),
			signalReceived: make(chan struct{}),
			signalDone:     make(chan error, 1),
			killReceived:   make(chan struct{}),
			killDone:       make(chan error, 1),
		}
		wrapper := launchCmdWatched(testLogger(t), "foo", cmd, 100*time.Millisecond)
		errClose := make(chan error)
		go func() {
			errClose <- wrapper.Close()
		}()
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(cmd.runReceived))
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(cmd.signalReceived))
		cmd.signalDone <- errors.New("signal error")
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(cmd.killReceived))
		cmd.killDone <- errors.New("kill error")
		assert.ErrorContains(t, testhelper.WaitForErrorWithTimeout(errClose), "timeout killing plugin")
	})
	t.Run("process is killed when graceful signalling fails", func(t *testing.T) {
		runErr := errors.New("run error")
		cmd := &mockCmd{
			runReceived:    make(chan struct{}),
			runDone:        make(chan error, 1),
			signalReceived: make(chan struct{}),
			signalDone:     make(chan error, 1),
			killReceived:   make(chan struct{}),
			killDone:       make(chan error, 1),
		}
		wrapper := launchCmdWatched(testLogger(t), "foo", cmd, time.Second)
		errClose := make(chan error)
		go func() {
			errClose <- wrapper.Close()
		}()
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(cmd.runReceived))
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(cmd.signalReceived))
		cmd.signalDone <- errors.New("signal error")
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(cmd.killReceived))
		cmd.runDone <- runErr
		cmd.killDone <- nil
		assert.ErrorIs(t, testhelper.WaitForErrorWithTimeout(errClose), runErr)
	})
	t.Run("process is terminated gracefully", func(t *testing.T) {
		runErr := errors.New("run error")
		cmd := &mockCmd{
			runReceived:    make(chan struct{}),
			runDone:        make(chan error, 1),
			signalReceived: make(chan struct{}),
			signalDone:     make(chan error, 1),
		}
		wrapper := launchCmdWatched(testLogger(t), "foo", cmd, time.Second)
		errClose := make(chan error)
		go func() {
			errClose <- wrapper.Close()
		}()
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(cmd.runReceived))
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(cmd.signalReceived))
		cmd.signalDone <- nil
		cmd.runDone <- runErr
		assert.ErrorIs(t, testhelper.WaitForErrorWithTimeout(errClose), runErr)
	})
}

func isClosed[T any](ch <-chan T) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
