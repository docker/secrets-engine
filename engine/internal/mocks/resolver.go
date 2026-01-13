package mocks

import (
	"context"
	"iter"

	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/engine/internal/registry"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

type MockResolverRuntime struct {
	name              api.Name
	version           api.Version
	err               error
	envelopes         []secrets.Envelope
	pattern           secrets.Pattern
	GetSecretRequests int
}

type Option func(*MockResolverRuntime)

func WithError(err error) Option {
	return func(r *MockResolverRuntime) {
		r.err = err
	}
}

func WithPattern(pattern secrets.Pattern) Option {
	return func(r *MockResolverRuntime) {
		r.pattern = pattern
	}
}

func NewMockResolverRuntime(name, version string, envelopes []secrets.Envelope, opts ...Option) *MockResolverRuntime {
	r := &MockResolverRuntime{
		name:      api.MustNewName(name),
		version:   api.MustNewVersion(version),
		envelopes: envelopes,
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.pattern == nil {
		r.pattern = secrets.MustParsePattern("**")
	}
	return r
}

func (m *MockResolverRuntime) GetSecrets(_ context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	m.GetSecretRequests++
	var envelopes []secrets.Envelope
	for _, envelope := range m.envelopes {
		if pattern.Match(envelope.ID) {
			envelopes = append(envelopes, envelope)
		}
	}
	return envelopes, m.err
}

func (m *MockResolverRuntime) Close() error {
	return nil
}

func (m *MockResolverRuntime) Name() api.Name {
	return m.name
}

func (m *MockResolverRuntime) Version() api.Version {
	return m.version
}

func (m *MockResolverRuntime) Pattern() secrets.Pattern {
	return m.pattern
}

func (m *MockResolverRuntime) Closed() <-chan struct{} {
	panic("implement me")
}

func (m *MockResolverRuntime) Type() plugin.Type {
	panic("implement me")
}

type MockResolverRegistry struct {
	Resolver []plugin.Runtime
}

func (m MockResolverRegistry) Iterator() iter.Seq[plugin.Runtime] {
	return NewMockIterator(m.Resolver)
}

func (m MockResolverRegistry) Register(plugin.Runtime) (registry.RemoveFunc, error) {
	panic("implement me")
}
