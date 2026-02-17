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

package secrets

import (
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvelopeJSON(t *testing.T) {
	envelope := &Envelope{}
	paniced := atomic.Bool{}
	t.Cleanup(func() {
		assert.Truef(t, paniced.Load(), "envelope marshal did not panic")
	})
	defer func() {
		if a := recover(); a != nil {
			t.Logf("recovered from panic, %v", a)
			paniced.Store(true)
		}
	}()
	_, _ = json.Marshal(envelope)
}
