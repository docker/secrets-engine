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

package plugin

import (
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func newSocketPair(t *testing.T) (net.Conn, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)
	local := os.NewFile(uintptr(fds[0]), "socketpair[0]")
	defer local.Close()
	peer := os.NewFile(uintptr(fds[1]), "socketpair[1]")
	t.Cleanup(func() { peer.Close() })
	conn, err := net.FileConn(local)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn, peer
}
