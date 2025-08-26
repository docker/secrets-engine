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
