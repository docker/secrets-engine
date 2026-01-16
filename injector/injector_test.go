package injector

import (
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/assert"

	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/telemetry"
	"github.com/docker/secrets-engine/x/testhelper"
)

func Test_resolveENV(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		value  string
		result string
		source string
		err    error
	}{
		{
			name: "no value but no secret",
			key:  "GH_TOKEN",
		},
		{
			name:   "no value and secret",
			key:    "FOO",
			result: "bar",
			source: sourceKey,
		},
		{
			name: "no value but invalid key",
			key:  "MY/*/VAR",
		},
		{
			name:   "value but not a secrets engine path",
			key:    "GH_TOKEN",
			value:  "some-value",
			result: "some-value",
		},
		{
			name:  "value but invalid path",
			key:   "GH_TOKEN",
			value: "se://my//path",
			err:   secrets.ErrInvalidPattern,
		},
		{
			name:  "value but no secret",
			key:   "GH_TOKEN",
			value: "se://bar",
			err:   secrets.ErrNotFound,
		},
		{
			name:   "value and first matched secret",
			key:    "GH_TOKEN",
			value:  "se://*/my-secret",
			result: "some-value",
			source: sourceValue,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := testhelper.NewTestTracker()
			r := &resolver{
				logger:  testhelper.TestLogger(t),
				tracker: tracker,
				resolver: &testhelper.MockResolver{
					Store: map[secrets.ID]string{
						secrets.MustParseID("1password/my-secret"): "some-value",
						secrets.MustParseID("FOO"):                 "bar",
						secrets.MustParseID("vault/my-secret"):     "some-other-value",
					},
				},
			}

			value, err := r.resolveENV(t.Context(), tt.key, tt.value)

			if tt.err != nil {
				assert.Empty(t, tracker.GetQueue())
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.result, value)
			if tt.value != value {
				assert.EventuallyWithT(t, func(collect *assert.CollectT) {
					assert.Equal(collect, []any{EventSecretsEngineInjectorEnvResolved{Source: tt.source}}, tracker.GetQueue())
				}, 2*time.Second, 100*time.Millisecond)
			} else {
				assert.Empty(t, tracker.GetQueue())
			}
		})
	}
}

func mockedRewriter(t *testing.T, legacyFallback bool) ContainerCreateRewriter {
	t.Helper()
	return ContainerCreateRewriter{r: &resolver{
		logger: testhelper.TestLogger(t),
		resolver: &testhelper.MockResolver{Store: map[secrets.ID]string{
			secrets.MustParseID("FOO"): "some-value",
			secrets.MustParseID("BAR"): "baz",
		}},
		tracker: telemetry.NoopTracker(),
	}, legacyFallback: legacyFallback}
}

func Test_ContainerCreateRequestRewrite(t *testing.T) {
	t.Run("no config", func(t *testing.T) {
		r := mockedRewriter(t, false)
		assert.Nil(t, r.ContainerCreateRequestRewrite(t.Context(), &container.CreateRequest{}))
	})
	t.Run("no errors, legacy fallback", func(t *testing.T) {
		r := mockedRewriter(t, true)
		req := &container.CreateRequest{
			Config: &container.Config{Env: []string{"FOO", "BAZ=se://FOO"}},
		}
		assert.Nil(t, r.ContainerCreateRequestRewrite(t.Context(), req))
		assert.Equal(t, []string{"FOO=some-value", "BAZ=some-value"}, req.Env)
	})
	t.Run("no errors, no legacy fallback", func(t *testing.T) {
		r := mockedRewriter(t, false)
		req := &container.CreateRequest{
			Config: &container.Config{Env: []string{"FOO", "BAZ=se://FOO"}},
		}
		assert.Nil(t, r.ContainerCreateRequestRewrite(t.Context(), req))
		assert.Equal(t, []string{"FOO", "BAZ=some-value"}, req.Env)
	})
	t.Run("invariant if no secrets", func(t *testing.T) {
		r := mockedRewriter(t, true)
		req := &container.CreateRequest{
			Config: &container.Config{Env: []string{"something", "GH_TOKEN=", "B*/R", "B/A/R = space before"}},
		}
		assert.Nil(t, r.ContainerCreateRequestRewrite(t.Context(), req))
		assert.Equal(t, []string{"something", "GH_TOKEN=", "B*/R", "B/A/R = space before"}, req.Env)
	})
}
