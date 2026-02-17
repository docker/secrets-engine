// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !windows

package ipc

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
)

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

func FakeTestCustom(fd int) Custom {
	return Custom{fd}
}

type FdWrapper struct {
	peer *os.File
}

func (p *FdWrapper) Close() error {
	return p.peer.Close()
}

func (p *FdWrapper) ToCustomCfg() Custom {
	return Custom{Fd: 3} // 0, 1, and 2 are reserved for stdin, stdout, and stderr -> we get the next
}

func NewConnectionPair(cmd *exec.Cmd) (net.Conn, *FdWrapper, error) {
	fds, err := newSocketFD()
	if err != nil {
		return nil, nil, err
	}
	filename := fmt.Sprintf("socketpair-%d:%d", fds[0], fds[1])
	local := os.NewFile(uintptr(fds[0]), filename+"[0]")
	defer local.Close()
	peer := os.NewFile(uintptr(fds[1]), filename+"[1]")
	localConn, err := net.FileConn(local)
	if err != nil {
		peer.Close()
		return nil, nil, fmt.Errorf("failed to create net.Conn for %s: %w", local.Name(), err)
	}
	cmd.ExtraFiles = []*os.File{peer}
	return localConn, &FdWrapper{peer}, nil
}

// FromCustomCfg is the counter part of ToCustomCfg().
// Turns an file descriptor back into a connection object.
func FromCustomCfg(cfg Custom) (io.ReadWriteCloser, error) {
	f := os.NewFile(uintptr(cfg.Fd), "fd #"+strconv.Itoa(cfg.Fd))
	if f == nil {
		return nil, fmt.Errorf("failed to open FD %d", cfg.Fd)
	}
	defer f.Close()
	conn, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create net.Conn for fd #%d: %w", cfg.Fd, err)
	}
	return conn, nil
}
