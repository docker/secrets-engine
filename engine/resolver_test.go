package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

type mockResolverRuntime struct {
	name      api.Name
	version   api.Version
	err       error
	envelopes []secrets.Envelope
}

func newMockResolverRuntime(name string, err ...error) runtime {
	return &mockResolverRuntime{
		name:      api.MustNewName(name),
		version:   api.MustNewVersion("v1"),
		err:       errors.Join(err...),
		envelopes: secrets.EnvelopeErrs(err...),
	}
}

func (m mockResolverRuntime) GetSecrets(context.Context, secrets.Request) ([]secrets.Envelope, error) {
	return m.envelopes, m.err
}

func (m mockResolverRuntime) Close() error {
	return nil
}

func (m mockResolverRuntime) Name() api.Name {
	return m.name
}

func (m mockResolverRuntime) Version() api.Version {
	return m.version
}

func (m mockResolverRuntime) Pattern() secrets.Pattern {
	return secrets.MustParsePattern("**")
}

func (m mockResolverRuntime) Closed() <-chan struct{} {
	panic("implement me")
}

type mockResolverRegistry struct {
	resolver []runtime
}

func (m mockResolverRegistry) Register(runtime) (removeFunc, error) {
	panic("implement me")
}

func (m mockResolverRegistry) GetAll() []runtime {
	return m.resolver
}

func TestResolver(t *testing.T) {
	t.Parallel()
	t.Run("no match but errors", func(t *testing.T) {
		errFoo1 := errors.New("foo")
		errFoo2 := errors.New("foo")
		errBar1 := errors.New("bar")
		errBar2 := errors.New("bar")
		reg := mockResolverRegistry{resolver: []runtime{
			newMockResolverRuntime("foo", errFoo1, errFoo2),
			newMockResolverRuntime("bar", errBar1, errBar2),
		}}
		resolver := &regResolver{reg: reg}
		_, err := resolver.GetSecrets(t.Context(), secrets.Request{Pattern: secrets.MustParsePattern("**")})
		assert.Error(t, err)
		assert.ErrorIs(t, err, errFoo1)
		assert.ErrorIs(t, err, errFoo2)
		assert.ErrorIs(t, err, errBar1)
		assert.ErrorIs(t, err, errBar2)
	})
	t.Run("no match no errors", func(t *testing.T) {
		reg := mockResolverRegistry{resolver: []runtime{}}
		resolver := &regResolver{reg: reg}
		_, err := resolver.GetSecrets(t.Context(), secrets.Request{Pattern: secrets.MustParsePattern("**")})
		assert.ErrorIs(t, err, secrets.ErrNotFound)
	})
	t.Run("multiple matches across multiple plugins", func(t *testing.T) {
		reg := mockResolverRegistry{resolver: []runtime{
			newMockResolverRuntime("foo", errors.New("foo")),
			mockResolverRuntime{
				name:    api.MustNewName("bar"),
				version: api.MustNewVersion("v1"),
				envelopes: []secrets.Envelope{
					{ID: secrets.MustParseID("foo"), Value: []byte("foo")},
					{ID: secrets.MustParseID("bar"), Value: []byte("bar")},
				},
			},
			mockResolverRuntime{
				name:    api.MustNewName("baz"),
				version: api.MustNewVersion("v1"),
				envelopes: []secrets.Envelope{
					{ID: secrets.MustParseID("baz"), Value: []byte("baz")},
				},
			},
		}}
		resolver := &regResolver{reg: reg}
		e, err := resolver.GetSecrets(t.Context(), secrets.Request{Pattern: secrets.MustParsePattern("**")})
		assert.NoError(t, err)
		require.Len(t, e, 3)
		assert.Equal(t, "foo", string(e[0].Value))
		assert.Equal(t, "bar", string(e[1].Value))
		assert.Equal(t, "baz", string(e[2].Value))
	})
}
