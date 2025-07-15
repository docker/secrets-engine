//go:build linux

package ipc

import (
	"golang.org/x/sys/unix"
)

func newSocketFD() ([2]int, error) {
	return unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
}
