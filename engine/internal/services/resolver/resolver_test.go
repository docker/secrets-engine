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
			mocks.NewMockResolverRuntime("foo", "v1", nil, mocks.WithError(errors.New("foo"))),
			mocks.NewMockResolverRuntime("bar", "v1", nil, mocks.WithError(errors.New("bar"))),
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
			mocks.NewMockResolverRuntime("foo", "v1", nil, mocks.WithError(errors.New("foo"))),
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
	t.Run("plugin patterns optimize per plugin requests", func(t *testing.T) {
		tests := []struct {
			name       string
			pattern    string
			nrResults  int
			nrRequests int
		}{
			{
				name:       "everything glob",
				pattern:    "**",
				nrResults:  3,
				nrRequests: 2,
			},
			{
				name:       "everything below glob",
				pattern:    "base/**",
				nrResults:  3,
				nrRequests: 2,
			},
			{
				name:       "everything inside plugin 1",
				pattern:    "base/sub1/*",
				nrResults:  2,
				nrRequests: 1,
			},
			{
				name:       "everything inside plugin 2",
				pattern:    "base/sub2/*",
				nrResults:  1,
				nrRequests: 1,
			},
			{
				name:       "specific secret",
				pattern:    "base/sub2/baz",
				nrResults:  1,
				nrRequests: 1,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				r1 := mocks.NewMockResolverRuntime("bar", "v1", []secrets.Envelope{
					{ID: secrets.MustParseID("base/sub1/foo"), Value: []byte("foo")},
					{ID: secrets.MustParseID("base/sub1/bar"), Value: []byte("bar")},
				}, mocks.WithPattern(secrets.MustParsePattern("base/sub1/*")))
				r2 := mocks.NewMockResolverRuntime("baz", "v1", []secrets.Envelope{
					{ID: secrets.MustParseID("base/sub2/baz"), Value: []byte("baz")},
				}, mocks.WithPattern(secrets.MustParsePattern("base/sub2/*")))
				reg := mocks.MockResolverRegistry{Resolver: []plugin.Runtime{r1, r2}}
				tracker := testhelper.NewTestTracker()
				resolver := NewService(testhelper.TestLogger(t), tracker, reg)
				e, err := resolver.GetSecrets(t.Context(), secrets.MustParsePattern(test.pattern))
				require.NoError(t, err)
				assert.Len(t, e, test.nrResults)
				assert.Equal(t, test.nrRequests, r1.GetSecretRequests+r2.GetSecretRequests)
			})
		}
	})
}
