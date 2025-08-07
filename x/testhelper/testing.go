package testhelper

import (
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/docker/secrets-engine/x/logging"
)

func WaitForErrorWithTimeout(in <-chan error) error {
	val, err := WaitForWithExplicitTimeoutV(in, 2*time.Second)
	if err != nil {
		return err
	}
	return val
}

func WaitForClosedWithTimeout(in <-chan struct{}) error {
	select {
	case <-in:
		return nil
	case <-time.After(4 * time.Second):
		return errors.New("timeout")
	}
}

func WaitForWithTimeoutV[T any](ch <-chan T) (T, error) {
	return WaitForWithExplicitTimeoutV(ch, 2*time.Second)
}

func WaitForWithExplicitTimeoutV[T any](ch <-chan T, timeout time.Duration) (T, error) {
	var zero T
	select {
	case val, ok := <-ch:
		if !ok {
			return zero, errors.New("channel closed")
		}
		return val, nil
	case <-time.After(timeout):
		return zero, errors.New("timeout")
	}
}

// RandomShortSocketName creates a socket name string that avoids common pitfalls in tests.
// There are a bunch of opposing problems in unit tests with sockets:
// Ideally, we'd like to use t.TmpDir+something.sock -> too long socket name
// We can't just use local short file name -> clashes when running tests in parallel
// We can't use t.ChDir + short name -> t.ChDir does not allow t.Parallel
// -> we use a short local but randomized socket path
func RandomShortSocketName() string {
	return randString(6) + ".sock"
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func TestLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewDefaultLogger(t.Name())
}
