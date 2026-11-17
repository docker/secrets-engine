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

package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/docker/secrets-engine/x/api"
)

type PluginConfigFromEngine struct {
	Name                string        `json:"name"`
	RegistrationTimeout time.Duration `json:"timeout"`
	Custom
}

func (c *PluginConfigFromEngine) ToString() (string, error) {
	result, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func NewPluginConfigFromEngineEnv(in string) (*PluginConfigFromEngine, error) {
	var result PluginConfigFromEngine
	if err := json.Unmarshal([]byte(in), &result); err != nil {
		return nil, fmt.Errorf("failed to decode plugin config from runtime %q: %w", api.PluginLaunchedByEngineVar, err)
	}
	if result.Name == "" {
		return nil, errors.New("plugin name is required")
	}
	if result.RegistrationTimeout == 0 {
		return nil, errors.New("plugin registration timeout is required")
	}
	if err := result.isValid(); err != nil {
		return nil, err
	}
	return &result, nil
}
