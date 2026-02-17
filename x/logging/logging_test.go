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

package logging

import (
	"bytes"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_logFilePrefix(t *testing.T) {
	t.Parallel()
	t.Run("printf", func(t *testing.T) {
		buf := &bytes.Buffer{}
		logger := &defaultLogger{logger: log.New(buf, "", log.LstdFlags), prefix: "prefix"}
		logger.Printf("foo")
		result := buf.String()
		assert.NotContains(t, result, "logging.go")
		assert.Contains(t, result, "logging_test.go")
	})
	t.Run("warnf", func(t *testing.T) {
		buf := &bytes.Buffer{}
		logger := &defaultLogger{logger: log.New(buf, "", log.LstdFlags), prefix: "prefix"}
		logger.Warnf("foo")
		result := buf.String()
		assert.NotContains(t, result, "logging.go")
		assert.Contains(t, result, "logging_test.go")
	})
	t.Run("errorf", func(t *testing.T) {
		buf := &bytes.Buffer{}
		logger := &defaultLogger{logger: log.New(buf, "", log.LstdFlags), prefix: "prefix"}
		logger.Errorf("foo")
		result := buf.String()
		assert.NotContains(t, result, "logging.go")
		assert.Contains(t, result, "logging_test.go")
	})
}
