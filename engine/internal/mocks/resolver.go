package mocks

import (
	"context"
	"errors"
	"iter"

	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/engine/internal/registry"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

type MockResolverRuntime struct {
	name      api.Name
	version   api.Version
	err       error
	envelopes []secrets.Envelope
}

func NewMockResolverRuntime(name, version string, envelopes []secrets.Envelope, err ...error) plugin.Runtime {
	return &MockResolverRuntime{
		name:      api.MustNewName(name),
		version:   api.MustNewVersion(version),
		envelopes: envelopes,
		err:       errors.Join(err...),
	}
}

func (m MockResolverRuntime) GetSecrets(context.Context, secrets.Pattern) ([]secrets.Envelope, error) {
	return m.envelopes, m.err
}

func (m MockResolverRuntime) Close() error {
	return nil
}

func (m MockResolverRuntime) Name() api.Name {
	return m.name
}

func (m MockResolverRuntime) Version() api.Version {
	return m.version
}

func (m MockResolverRuntime) Pattern() secrets.Pattern {
	return secrets.MustParsePattern("**")
}

func (m MockResolverRuntime) Closed() <-chan struct{} {
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
