package posixage

import (
	"errors"
	"os"
)

var (
	ErrLockUnsuccessful   = errors.New("store is locked")
	ErrUnlockUnsuccessful = errors.New("could not unlock store")
)

const lockFileName = ".posixage.lock"

type unlockFunc func() error

func openFile(root *os.Root) (*os.File, error) {
	fl, err := root.OpenFile(lockFileName, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	return fl, nil
}
