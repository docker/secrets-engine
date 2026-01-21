package mocks

import (
	"context"

	"github.com/docker/secrets-engine/runtime/internal/plugin"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

type MockRuntime struct {
	RuntimeName   api.Name
	CloseCalled   int
	RuntimeClosed chan struct{}
}

var _ plugin.Runtime = &MockRuntime{}

func (m *MockRuntime) Name() api.Name {
	return m.RuntimeName
}

func (m *MockRuntime) Version() api.Version {
	return MockValidVersion
}

func (m *MockRuntime) Pattern() secrets.Pattern {
	return MockPatternAny
}

func (m *MockRuntime) GetSecrets(context.Context, secrets.Pattern) ([]secrets.Envelope, error) {
	return []secrets.Envelope{}, nil
}

func (m *MockRuntime) Close() error {
	m.CloseCalled++
	return nil
}

func (m *MockRuntime) Closed() <-chan struct{} {
	return m.RuntimeClosed
}
