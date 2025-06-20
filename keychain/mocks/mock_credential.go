package mocks

import (
	"bytes"
	"errors"

	"github.com/docker/secrets-engine/keychain"
)

type MockCredential struct {
	Username string
	Password string
}

var _ keychain.Secret = &MockCredential{}

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
