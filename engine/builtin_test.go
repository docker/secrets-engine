package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/plugin"
)

type mockInternalPlugin struct {
	pattern         secrets.Pattern
	errGetSecretErr error
	blockRunForever chan struct{}
	runPanics       bool
	getSecretPanics bool
	secrets         map[secrets.ID]string
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
	<-ctx.Done()
	return nil
}

func Test_internalRuntime(t *testing.T) {
	SetPluginShutdownTimeout(100 * time.Millisecond)
	t.Parallel()
	t.Run("no runtime for plugins with invalid pattern", func(t *testing.T) {
		m := &mockInternalPlugin{}
		_, err := newInternalRuntime(t.Context(), "foo", m)
		assert.ErrorIs(t, err, secrets.ErrInvalidPattern)
	})
	t.Run("start / get secret -> value / stop / get secret -> no value", func(t *testing.T) {
		name := "foo"
		m := &mockInternalPlugin{pattern: "*", secrets: map[secrets.ID]string{mockSecretID: mockSecretValue}}
		r, err := newInternalRuntime(t.Context(), name, m)
		assert.NoError(t, err)
		assert.Equal(t, pluginData{
			name:       name,
			pattern:    "*",
			version:    mockVersion,
			pluginType: builtinPlugin,
		}, r.Data())
		resp, err := r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.NoError(t, err)
		assert.Equal(t, resp.Value, []byte(mockSecretValue))
		assert.NoError(t, r.Close())
		assert.NoError(t, checkClosed(r.Closed()))
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorContains(t, err, "plugin foo has been shutdown")
	})
	t.Run("get secret -> forward error", func(t *testing.T) {
		errGetSecretErr := errors.New("getSecret error")
		m := &mockInternalPlugin{pattern: "*", errGetSecretErr: errGetSecretErr}
		r, err := newInternalRuntime(t.Context(), "foo", m)
		assert.NoError(t, err)
		resp, err := r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorIs(t, err, errGetSecretErr)
		assert.Equal(t, resp.Error, errGetSecretErr.Error())
	})
	t.Run("Blocking Run() on shutdown does not block but triggers an error", func(t *testing.T) {
		m := &mockInternalPlugin{pattern: "*", blockRunForever: make(chan struct{})}
		r, err := newInternalRuntime(t.Context(), "foo", m)
		assert.NoError(t, err)
		assert.ErrorContains(t, r.Close(), "timeout")
		assert.NoError(t, checkClosed(r.Closed()))
	})
	t.Run("panic in Run() is handled and does not block get secret", func(t *testing.T) {
		m := &mockInternalPlugin{pattern: "*", runPanics: true}
		r, err := newInternalRuntime(t.Context(), "foo", m)
		assert.NoError(t, err)
		assert.NoError(t, checkClosed(r.Closed()))
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorContains(t, err, "panic in foo:")
		assert.ErrorContains(t, r.Close(), "panic in foo:")
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorContains(t, err, "panic in foo:")
	})
	t.Run("panic in GetSecret is handled", func(t *testing.T) {
		m := &mockInternalPlugin{pattern: "*", getSecretPanics: true}
		r, err := newInternalRuntime(t.Context(), "bar", m)
		assert.NoError(t, err)
		_, err = r.GetSecret(t.Context(), secrets.Request{ID: mockSecretID})
		assert.ErrorContains(t, err, "recovering from panic in plugin bar")
	})
}
