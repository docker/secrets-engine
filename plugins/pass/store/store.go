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

package store

import (
	"context"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/keychain"
)

var _ store.Secret = &PassValue{}

type PassValue struct {
	Value []byte `json:"value"`
}

func (m *PassValue) Marshal() ([]byte, error) {
	return m.Value, nil
}

func (m *PassValue) Unmarshal(data []byte) error {
	m.Value = data
	return nil
}

func (m *PassValue) Metadata() map[string]string {
	return nil
}

func (m *PassValue) SetMetadata(map[string]string) error {
	return nil
}

func PassStore(serviceGroup string, opts ...keychain.Option) (store.Store, error) {
	kc, err := keychain.New(
		serviceGroup,
		"docker-pass-cli",
		func(_ context.Context, _ store.ID) *PassValue {
			return &PassValue{}
		},
		opts...,
	)
	return kc, err
}
