package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

const (
	mockSecretValue = "mockSecretValue"
	mockSecretID    = "mockSecretID"
)

var (
	mockSecretIDNew   = secrets.MustParseID("mockSecretID")
	mockSecretPattern = secrets.MustParsePattern("mockSecretID")
)

type mockInternalPlugin struct {
	errGetSecretErr error
	blockRunForever chan struct{}
	runPanics       bool
	getSecretPanics bool
	secrets         map[secrets.ID]string
	runExitCh       chan struct{}
}

func (m *mockInternalPlugin) GetSecrets(_ context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	if m.getSecretPanics {
		panic("panic")
	}
	if m.errGetSecretErr != nil {
		return nil, m.errGetSecretErr
	}
	var result []secrets.Envelope
	for id, v := range m.secrets {
		if pattern.Match(id) {
			result = append(result, secrets.Envelope{ID: id, Value: []byte(v)})
		}
	}
	return result, nil
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
	const shutdownTimeout = 100 * time.Millisecond
	mockConfig := &configValidated{api.MustNewName("foo"), api.MustNewVersion("v5"), mockPatternAny}

	t.Parallel()
	t.Run("start / get secret -> value / stop / get secret -> no value", func(t *testing.T) {
		m := &mockInternalPlugin{secrets: map[secrets.ID]string{mockSecretIDNew: mockSecretValue}}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig, shutdownTimeout)
		require.NoError(t, err)
		assert.Equal(t, "foo", r.Name().String())
		assert.Equal(t, "v5", r.Version().String())
		assert.Equal(t, "*", r.Pattern().String())
		resp, err := r.GetSecrets(t.Context(), mockSecretPattern)
		require.NoError(t, err)
		require.NotEmpty(t, resp)
		assert.Equal(t, resp[0].Value, []byte(mockSecretValue))
		assert.NoError(t, r.Close())
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
		_, err = r.GetSecrets(t.Context(), mockSecretPattern)
		assert.ErrorContains(t, err, "plugin foo has been shutdown")
	})
	t.Run("get secret -> forward error", func(t *testing.T) {
		errGetSecretErr := errors.New("getSecret error")
		m := &mockInternalPlugin{errGetSecretErr: errGetSecretErr}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig, shutdownTimeout)
		assert.NoError(t, err)
		_, err = r.GetSecrets(t.Context(), mockSecretPattern)
		assert.ErrorIs(t, err, errGetSecretErr)
	})
	t.Run("Blocking Run() on shutdown does not block but triggers an error", func(t *testing.T) {
		m := &mockInternalPlugin{blockRunForever: make(chan struct{})}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig, shutdownTimeout)
		assert.NoError(t, err)
		assert.ErrorContains(t, r.Close(), "timeout")
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
	})
	t.Run("panic in Run() is handled and does not block get secret", func(t *testing.T) {
		m := &mockInternalPlugin{runPanics: true}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig, shutdownTimeout)
		assert.NoError(t, err)
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
		_, err = r.GetSecrets(t.Context(), mockSecretPattern)
		assert.ErrorContains(t, err, "panic in foo:")
		assert.ErrorContains(t, r.Close(), "panic in foo:")
		_, err = r.GetSecrets(t.Context(), mockSecretPattern)
		assert.ErrorContains(t, err, "panic in foo:")
	})
	t.Run("Run() terminating too early without error creates 'stopped unexpectedly' error", func(t *testing.T) {
		runCh := make(chan struct{})
		m := &mockInternalPlugin{runExitCh: runCh}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig, shutdownTimeout)
		assert.NoError(t, err)
		close(runCh)
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
		assert.ErrorContains(t, r.Close(), "stopped unexpectedly")
	})
	t.Run("panic in GetSecrets is handled", func(t *testing.T) {
		m := &mockInternalPlugin{getSecretPanics: true}
		r, err := newInternalRuntime(testLoggerCtx(t), m, mockConfig, shutdownTimeout)
		assert.NoError(t, err)
		_, err = r.GetSecrets(t.Context(), mockSecretPattern)
		assert.ErrorContains(t, err, "recovering from panic in plugin foo")
	})
}
