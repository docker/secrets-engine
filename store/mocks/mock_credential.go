package mocks

import (
	"bytes"
	"errors"

	"github.com/docker/secrets-engine/store"
)

type MockCredential struct {
	Username   string
	Password   string
	Attributes map[string]string
}

// Metadata implements store.Secret.
func (m *MockCredential) Metadata() map[string]string {
	return m.Attributes
}

// SetMetadata implements store.Secret.
func (m *MockCredential) SetMetadata(attributes map[string]string) error {
	m.Attributes = attributes
	return nil
}

var _ store.Secret = &MockCredential{}

// Marshal implements secrets.Secret.
func (m *MockCredential) Marshal() ([]byte, error) {
	return []byte(m.Username + ":" + m.Password), nil
}

// Unmarshal implements secrets.Secret.
func (m *MockCredential) Unmarshal(data []byte) error {
	items := bytes.Split(data, []byte(":"))
	if len(items) != 2 {
		return errors.New("failed to unmarshal data into mock credential type")
	}
	m.Username = string(items[0])
	m.Password = string(items[1])
	return nil
}
