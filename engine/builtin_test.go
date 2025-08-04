package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/internal/api"
	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/internal/testhelper"
)

const (
	mockSecretValue = "mockSecretValue"
	mockSecretID    = secrets.ID("mockSecretID")
)

var mockVersion = "mockVersion"

type mockInternalPlugin struct {
	errGetSecretErr error
	blockRunForever chan struct{}
	runPanics       bool
	getSecretPanics bool
	secrets         map[secrets.ID]string
	runExitCh       chan struct{}
}

func (m *mockInternalPlugin) GetSecret(_ context.Context, request secrets.Request) (secrets.Envelope, error) {
	if m.getSecretPanics {
		panic("panic")
	}
	if m.errGetSecretErr != nil {
		return secrets.EnvelopeErr(request, m.errGetSecretErr), m.errGetSecretErr
	}
	for k, v := range m.secrets {
		if k == request.ID {
			return secrets.Envelope{ID: k, Value: []byte(v)}, nil
		}
	}
	return secrets.EnvelopeErr(request, secrets.ErrNotFound), secrets.ErrNotFound
}

func (m *mockInternalPlugin) Run(ctx context.Context) error {
	if m.runPanics {
		panic("panic")
	}
	if m.blockRunForever != nil {
		<-m.blockRunForever
	}
	if m.runExitCh != nil {
		select {
		case <-m.runExitCh:
		case <-ctx.Done():
		}
	} else {
		<-ctx.Done()
	}
	return nil
}

func Test_internalRuntime(t *testing.T) {
	// TODO: relying on a global variable for tests is bad -> fix this!
	SetPluginShutdownTimeout(100 * time.Millisecond)
	mockConfig := Config{Name: "foo", Pattern: "*", Version: api.MustNewVersion("5")}

	t.Parallel()
	t.Run("no runtime for plugins with invalid config", func(t *testing.T) {
		m := &mockInternalPlugin{}
		_, err := newInternalRuntime(testLoggerCtx(t), m, Config{})
		assert.Error(t, err)
	})
	t.Run("start / get secret -> value / stop / get secret -> no value", func(t *testing.T) {
		m := &mockInternalPlugin{secrets: map[secrets.ID]string{mockSecretID: mockSecretValue}}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig)
		require.NoError(t, err)
		assert.Equal(t, "foo", r.Data().Name())
		assert.Equal(t, "5", r.Data().Version())
		assert.Equal(t, "*", string(r.Data().Pattern()))
		resp, err := r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.NoError(t, err)
		assert.Equal(t, resp.Value, []byte(mockSecretValue))
		assert.NoError(t, r.Close())
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorContains(t, err, "plugin foo has been shutdown")
	})
	t.Run("get secret -> forward error", func(t *testing.T) {
		errGetSecretErr := errors.New("getSecret error")
		m := &mockInternalPlugin{errGetSecretErr: errGetSecretErr}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig)
		assert.NoError(t, err)
		resp, err := r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorIs(t, err, errGetSecretErr)
		assert.Equal(t, resp.Error, errGetSecretErr.Error())
	})
	t.Run("Blocking Run() on shutdown does not block but triggers an error", func(t *testing.T) {
		m := &mockInternalPlugin{blockRunForever: make(chan struct{})}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig)
		assert.NoError(t, err)
		assert.ErrorContains(t, r.Close(), "timeout")
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
	})
	t.Run("panic in Run() is handled and does not block get secret", func(t *testing.T) {
		m := &mockInternalPlugin{runPanics: true}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig)
		assert.NoError(t, err)
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorContains(t, err, "panic in foo:")
		assert.ErrorContains(t, r.Close(), "panic in foo:")
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorContains(t, err, "panic in foo:")
	})
	t.Run("Run() terminating too early without error creates 'stopped unexpectedly' error", func(t *testing.T) {
		runCh := make(chan struct{})
		m := &mockInternalPlugin{runExitCh: runCh}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig)
		assert.NoError(t, err)
		close(runCh)
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
		assert.ErrorContains(t, r.Close(), "stopped unexpectedly")
	})
	t.Run("panic in GetSecret is handled", func(t *testing.T) {
		m := &mockInternalPlugin{getSecretPanics: true}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig)
		assert.NoError(t, err)
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorContains(t, err, "recovering from panic in plugin foo")
	})
}
