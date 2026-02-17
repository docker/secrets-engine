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

package posixage

import "github.com/docker/secrets-engine/x/logging"

type noopLogger struct{}

func (n *noopLogger) Errorf(_ string, _ ...any) {
}

func (n *noopLogger) Printf(_ string, _ ...any) {
}

func (n *noopLogger) Warnf(_ string, _ ...any) {
}

var _ logging.Logger = &noopLogger{}
