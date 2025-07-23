package testhelper

import (
	"errors"
	"time"
)

func WaitForWithTimeout[T any](ch <-chan T) error {
	return WaitForWithExplicitTimeout(ch, 2*time.Second)
}

func WaitForWithExplicitTimeout[T any](ch <-chan T, timeout time.Duration) error {
	select {
	case val, ok := <-ch:
		if !ok {
			return nil
		}
		if err, isErr := any(val).(error); isErr {
			return err
		}
		return nil
	case <-time.After(timeout):
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
