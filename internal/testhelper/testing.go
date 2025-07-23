package testhelper

import (
	"errors"
	"time"
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
	case <-time.After(2 * time.Second):
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
