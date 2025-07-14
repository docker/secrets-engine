//go:build windows

package ipc

import "errors"

type Custom struct {
	R uint64 `json:"r"`
	W uint64 `json:"w"`
}

func (c *Custom) isValid() error {
	if c.R == 0 || c.W == 0 {
		return errors.New("invalid pipe handlers")
	}
	return nil
}

func fakeCustom(fd int) Custom {
	return Custom{R: uint64(fd), W: uint64(fd + 1)}
}
