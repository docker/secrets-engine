package builtin

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/engine/internal/mocks"
	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

const (
	mockSecretValue = "mockSecretValue"
)

var (
	mockSecretIDNew   = secrets.MustParseID("mockSecretID")
	mockSecretPattern = secrets.MustParsePattern("mockSecretID")
)

func Test_internalRuntime(t *testing.T) {
	const shutdownTimeout = 100 * time.Millisecond
	mockConfig, err := plugin.NewValidatedConfig(plugin.Unvalidated{Name: "foo", Version: "v5", Pattern: "*"})
	require.NoError(t, err)

	t.Parallel()
	t.Run("start / get secret -> value / stop / get secret -> no value", func(t *testing.T) {
		m := &mocks.MockInternalPlugin{Secrets: map[secrets.ID]string{mockSecretIDNew: mockSecretValue}}
		r, err := NewInternalRuntime(testhelper.TestLoggerCtx(t), m, mockConfig, shutdownTimeout)
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
		m := &mocks.MockInternalPlugin{ErrGetSecretErr: errGetSecretErr}
		r, err := NewInternalRuntime(testhelper.TestLoggerCtx(t), m, mockConfig, shutdownTimeout)
		assert.NoError(t, err)
		_, err = r.GetSecrets(t.Context(), mockSecretPattern)
		assert.ErrorIs(t, err, errGetSecretErr)
	})
	t.Run("Blocking Run() on shutdown does not block but triggers an error", func(t *testing.T) {
		m := &mocks.MockInternalPlugin{BlockRunForever: make(chan struct{})}
		r, err := NewInternalRuntime(testhelper.TestLoggerCtx(t), m, mockConfig, shutdownTimeout)
		assert.NoError(t, err)
		assert.ErrorContains(t, r.Close(), "timeout")
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
	})
	t.Run("panic in Run() is handled and does not block get secret", func(t *testing.T) {
		m := &mocks.MockInternalPlugin{RunPanics: true}
		r, err := NewInternalRuntime(testhelper.TestLoggerCtx(t), m, mockConfig, shutdownTimeout)
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
		m := &mocks.MockInternalPlugin{RunExitCh: runCh}
		r, err := NewInternalRuntime(testhelper.TestLoggerCtx(t), m, mockConfig, shutdownTimeout)
		assert.NoError(t, err)
		close(runCh)
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(r.Closed()))
		assert.ErrorContains(t, r.Close(), "stopped unexpectedly")
	})
	t.Run("panic in GetSecrets is handled", func(t *testing.T) {
		m := &mocks.MockInternalPlugin{GetSecretPanics: true}
		r, err := NewInternalRuntime(testhelper.TestLoggerCtx(t), m, mockConfig, shutdownTimeout)
		assert.NoError(t, err)
		_, err = r.GetSecrets(t.Context(), mockSecretPattern)
		assert.ErrorContains(t, err, "recovering from panic in plugin foo")
	})
}
