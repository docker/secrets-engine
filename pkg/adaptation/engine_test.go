package adaptation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/docker/secrets-engine/pkg/secrets"
)

type mockRuntime struct {
	name string
}

func (m *mockRuntime) GetSecret(context.Context, secrets.Request) (secrets.Envelope, error) {
	return secrets.Envelope{}, nil
}

func (m *mockRuntime) Close() error {
	time.Sleep(10 * time.Millisecond)
	return fmt.Errorf("%s closed", m.name)
}

func (m *mockRuntime) Data() pluginData {
	return pluginData{}
}

// Unfortunately, there's no way to test this reliably using channels.
// We instead have a tiny sleep per mockRuntime.Close() with a larger global timeout in case the parallelStop function locks.
func Test_parallelStop(t *testing.T) {
	var runtimes []runtime
	for i := 0; i < 10000; i++ {
		runtimes = append(runtimes, &mockRuntime{name: fmt.Sprintf("r%d", i)})
	}
	stopErr := make(chan error)
	go func() {
		stopErr <- parallelStop(runtimes)
	}()
	select {
	case err := <-stopErr:
		assert.ErrorContains(t, err, "r24")
		assert.ErrorContains(t, err, "r32")
	case <-time.After(time.Second):
		t.Fatal("timeout: parallel stop should not exceed 1s")
	}
}
