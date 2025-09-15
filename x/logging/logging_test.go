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
