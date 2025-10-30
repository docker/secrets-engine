package resolver

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

func TestResolver(t *testing.T) {
	t.Parallel()
	t.Run("no match but errors", func(t *testing.T) {
		tracker := testhelper.NewTestTracker()
		reg := mocks.MockResolverRegistry{Resolver: []plugin.Runtime{
			mocks.NewMockResolverRuntime("foo", "v1", nil, errors.New("foo")),
			mocks.NewMockResolverRuntime("bar", "v1", nil, errors.New("bar")),
		}}
		res := NewService(testhelper.TestLogger(t), tracker, reg)
		_, err := res.GetSecrets(t.Context(), secrets.MustParsePattern("**"))
		assert.ErrorIs(t, err, secrets.ErrNotFound)
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			assert.Equal(collect, []any{EventSecretsEngineRequest{}}, tracker.GetQueue())
		}, 2*time.Second, 100*time.Millisecond)
	})
	t.Run("no match no errors", func(t *testing.T) {
		tracker := testhelper.NewTestTracker()
		reg := mocks.MockResolverRegistry{Resolver: []plugin.Runtime{}}
		resolver := NewService(testhelper.TestLogger(t), tracker, reg)
		_, err := resolver.GetSecrets(t.Context(), secrets.MustParsePattern("**"))
		assert.ErrorIs(t, err, secrets.ErrNotFound)
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			assert.Equal(collect, []any{EventSecretsEngineRequest{}}, tracker.GetQueue())
		}, 2*time.Second, 100*time.Millisecond)
	})
	t.Run("multiple matches across multiple plugins", func(t *testing.T) {
		reg := mocks.MockResolverRegistry{Resolver: []plugin.Runtime{
			mocks.NewMockResolverRuntime("foo", "v1", nil, errors.New("foo")),
			mocks.NewMockResolverRuntime("bar", "v1", []secrets.Envelope{
				{ID: secrets.MustParseID("foo"), Value: []byte("foo")},
				{ID: secrets.MustParseID("bar"), Value: []byte("bar")},
			}),
			mocks.NewMockResolverRuntime("baz", "v1", []secrets.Envelope{
				{ID: secrets.MustParseID("baz"), Value: []byte("baz")},
			}),
		}}
		tracker := testhelper.NewTestTracker()
		resolver := NewService(testhelper.TestLogger(t), tracker, reg)
		e, err := resolver.GetSecrets(t.Context(), secrets.MustParsePattern("**"))
		assert.NoError(t, err)
		require.Len(t, e, 3)
		assert.Equal(t, "foo", string(e[0].Value))
		assert.Equal(t, "bar", string(e[1].Value))
		assert.Equal(t, "baz", string(e[2].Value))
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			assert.Equal(collect, []any{EventSecretsEngineRequest{ResultsTotal: 3}}, tracker.GetQueue())
		}, 2*time.Second, 100*time.Millisecond)
	})
}
