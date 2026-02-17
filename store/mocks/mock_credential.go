// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
