package mocks

import (
	"context"

	"github.com/docker/secrets-engine/x/secrets"
)

type MockInternalPlugin struct {
	ErrGetSecretErr error
	BlockRunForever chan struct{}
	RunPanics       bool
	GetSecretPanics bool
	Secrets         map[secrets.ID]string
	RunExitCh       chan struct{}
}

func (m *MockInternalPlugin) GetSecrets(_ context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	if m.GetSecretPanics {
		panic("panic")
	}
	if m.ErrGetSecretErr != nil {
		return nil, m.ErrGetSecretErr
	}
	var result []secrets.Envelope
	for id, v := range m.Secrets {
		if pattern.Match(id) {
			result = append(result, secrets.Envelope{ID: id, Value: []byte(v)})
		}
	}
	return result, nil
}

func (m *MockInternalPlugin) Run(ctx context.Context) error {
	if m.RunPanics {
		panic("panic")
	}
	if m.BlockRunForever != nil {
		<-m.BlockRunForever
	}
	if m.RunExitCh != nil {
		select {
		case <-m.RunExitCh:
		case <-ctx.Done():
		}
	} else {
		<-ctx.Done()
	}
	return nil
}
