package adaptation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/docker/secrets-engine/pkg/secrets"
)

type mockSlowRuntime struct {
	name string
}

func (m *mockSlowRuntime) GetSecret(context.Context, secrets.Request) (secrets.Envelope, error) {
	return secrets.Envelope{}, nil
}

func (m *mockSlowRuntime) Close() error {
	time.Sleep(10 * time.Millisecond)
	return fmt.Errorf("%s closed", m.name)
}

func (m *mockSlowRuntime) Data() pluginData {
	return pluginData{}
}

// Unfortunately, there's no way to test this reliably using channels.
// We instead have a tiny sleep per mockRuntime.Close() with a larger global timeout in case the parallelStop function locks.
func Test_parallelStop(t *testing.T) {
	var runtimes []runtime
	for i := 0; i < 10000; i++ {
		runtimes = append(runtimes, &mockSlowRuntime{name: fmt.Sprintf("r%d", i)})
	}
	stopErr := make(chan error)
	go func() {
		stopErr <- parallelStop(runtimes)
	}()
	select {
	case err := <-stopErr:
		assert.ErrorContains(t, err, "r24")
		assert.ErrorContains(t, err, "r32")
	case <-time.After(time.Second):
		t.Fatal("timeout: parallel stop should not exceed 1s")
	}
}

type mockRuntime struct {
	closeCalled int
}

func (m *mockRuntime) GetSecret(context.Context, secrets.Request) (secrets.Envelope, error) {
	return secrets.Envelope{}, nil
}

func (m *mockRuntime) Close() error {
	m.closeCalled++
	return nil
}

func (m *mockRuntime) Data() pluginData {
	return pluginData{}
}

type mockRegistry struct {
	addCalled    []runtime
	removed      chan struct{}
	removeCalled int
	err          error
}

func (m *mockRegistry) Register(plugin runtime) (removeFunc, error) {
	m.addCalled = append(m.addCalled, plugin)
	return func() {
		m.removeCalled++
		if m.removed != nil {
			close(m.removed)
		}
	}, m.err
}

func (m *mockRegistry) GetAll() []runtime {
	return nil
}

func Test_Register(t *testing.T) {
	t.Run("nothing gets registered when launch returns an error", func(t *testing.T) {
		reg := &mockRegistry{}
		launchErr := errors.New("launch error")
		l := func() (runtime, <-chan struct{}, error) {
			return nil, nil, launchErr
		}
		assert.ErrorIs(t, register(reg, l), launchErr)
	})
	t.Run("when Register() returns an error, Close() is called", func(t *testing.T) {
		errRegister := errors.New("register error")
		reg := &mockRegistry{err: errRegister}
		r := &mockRuntime{}
		l := func() (runtime, <-chan struct{}, error) {
			return r, nil, nil
		}
		assert.ErrorIs(t, register(reg, l), errRegister)
		assert.Equal(t, 1, r.closeCalled)
	})
	t.Run("runtime gets unregistered when channel is closed", func(t *testing.T) {
		reg := &mockRegistry{removed: make(chan struct{})}
		r := &mockRuntime{}
		done := make(chan struct{})
		l := func() (runtime, <-chan struct{}, error) {
			return r, done, nil
		}
		assert.NoError(t, register(reg, l))
		assert.Equal(t, 0, reg.removeCalled)
		close(done)
		<-reg.removed
		assert.Equal(t, 1, reg.removeCalled)
		assert.Equal(t, 0, r.closeCalled)
	})
	t.Run("runtime gets unregistered when channel is nil", func(t *testing.T) {
		reg := &mockRegistry{removed: make(chan struct{})}
		r := &mockRuntime{}
		l := func() (runtime, <-chan struct{}, error) {
			return r, nil, nil
		}
		assert.NoError(t, register(reg, l))
		<-reg.removed
		assert.Equal(t, 1, reg.removeCalled)
		assert.Equal(t, 0, r.closeCalled)
	})
}
