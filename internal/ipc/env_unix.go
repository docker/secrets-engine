//go:build !windows

package ipc

import "errors"

type Custom struct {
	Fd int `json:"fd"`
}

func (c *Custom) isValid() error {
	if c.Fd <= 2 {
		// File descriptors 0, 1, and 2 are reserved for stdin, stdout, and stderr.
		return errors.New("invalid file descriptor for plugin connection")
	}
	return nil
}

func fakeCustom(fd int) Custom {
	return Custom{fd}
}
