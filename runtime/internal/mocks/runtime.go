package mocks

import (
	"context"

	"github.com/docker/secrets-engine/x/secrets"
)

const (
	mockSecretValue = "mockSecretValue"
)

var mockSecretIDNew = secrets.MustParseID("mockSecretID")

type MockedPlugin struct {
	id secrets.ID
}

type MockedPluginOption func(*MockedPlugin)

func NewMockedPlugin(options ...MockedPluginOption) *MockedPlugin {
	m := &MockedPlugin{
		id: mockSecretIDNew,
	}
	for _, opt := range options {
		opt(m)
	}
	return m
}

func WithID(id secrets.ID) MockedPluginOption {
	return func(mp *MockedPlugin) {
		mp.id = id
	}
}

func (m *MockedPlugin) GetSecrets(_ context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	if pattern.Match(m.id) {
		return []secrets.Envelope{{ID: m.id, Value: []byte(mockSecretValue)}}, nil
	}
	return nil, secrets.ErrNotFound
}
