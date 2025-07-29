package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/internal/testhelper"
	"github.com/docker/secrets-engine/plugin"
)

const (
	mockVersion     = "mockVersion"
	mockSecretValue = "mockSecretValue"
)

var mockSecretID = secrets.MustNewID("mockSecretID")

type mockInternalPlugin struct {
	pattern         secrets.Pattern
	errGetSecretErr error
	blockRunForever chan struct{}
	runPanics       bool
	getSecretPanics bool
	secrets         map[string]string
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
		if k == request.ID.String() {
			return secrets.Envelope{ID: secrets.MustNewID(k), Value: []byte(v)}, nil
		}
	}
	return secrets.EnvelopeErr(request, secrets.ErrNotFound), secrets.ErrNotFound
}

func (m *mockInternalPlugin) Config() plugin.Config {
	return plugin.Config{
		Pattern: m.pattern,
		Version: mockVersion,
	}
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
	SetPluginShutdownTimeout(100 * time.Millisecond)
	t.Parallel()
	pattern := secrets.MustParsePattern("*")

	t.Run("start / get secret -> value / stop / get secret -> no value", func(t *testing.T) {
		name := "foo"
		m := &mockInternalPlugin{pattern: pattern, secrets: map[string]string{mockSecretID.String(): mockSecretValue}}
		r, err := newInternalRuntime(testLoggerCtx(t), name, m)
		assert.NoError(t, err)
		assert.Equal(t, pluginData{
			name:       name,
			pattern:    pattern,
			version:    mockVersion,
			pluginType: builtinPlugin,
		}, r.Data())
		resp, err := r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		require.NoError(t, err)
		assert.Equal(t, resp.Value, []byte(mockSecretValue))
		assert.NoError(t, r.Close())
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorContains(t, err, "plugin foo has been shutdown")
	})
	t.Run("get secret -> forward error", func(t *testing.T) {
		errGetSecretErr := errors.New("getSecret error")
		m := &mockInternalPlugin{pattern: pattern, errGetSecretErr: errGetSecretErr}
		r, err := newInternalRuntime(testLoggerCtx(t), "foo", m)
		require.NoError(t, err)
		resp, err := r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		require.ErrorIs(t, err, errGetSecretErr)
		assert.Equal(t, resp.Error, errGetSecretErr.Error())
	})
	t.Run("Blocking Run() on shutdown does not block but triggers an error", func(t *testing.T) {
		m := &mockInternalPlugin{pattern: pattern, blockRunForever: make(chan struct{})}
		r, err := newInternalRuntime(testLoggerCtx(t), "foo", m)
		require.NoError(t, err)
		assert.ErrorContains(t, r.Close(), "timeout")
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
	})
	t.Run("panic in Run() is handled and does not block get secret", func(t *testing.T) {
		m := &mockInternalPlugin{pattern: pattern, runPanics: true}
		r, err := newInternalRuntime(testLoggerCtx(t), "foo", m)
		require.NoError(t, err)
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		require.Error(t, err)
		assert.ErrorContains(t, err, "panic in foo:")
		assert.ErrorContains(t, r.Close(), "panic in foo:")
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorContains(t, err, "panic in foo:")
	})
	t.Run("Run() terminating too early without error creates 'stopped unexpectedly' error", func(t *testing.T) {
		runCh := make(chan struct{})
		m := &mockInternalPlugin{pattern: secrets.MustParsePattern("*"), runExitCh: runCh}
		r, err := newInternalRuntime(testLoggerCtx(t), "foo", m)
		require.NoError(t, err)
		close(runCh)
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
		assert.ErrorContains(t, r.Close(), "stopped unexpectedly")
	})
	t.Run("panic in GetSecret is handled", func(t *testing.T) {
		m := &mockInternalPlugin{pattern: pattern, getSecretPanics: true}
		r, err := newInternalRuntime(testLoggerCtx(t), "bar", m)
		require.NoError(t, err)
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		require.Error(t, err)
		assert.ErrorContains(t, err, "recovering from panic in plugin bar")
	})
}
