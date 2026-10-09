// Copyright 2026 Docker, Inc.
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

package prompt

import (
	"bytes"
	"context"
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_terminalInput(t *testing.T) {
	t.Parallel()
	for _, selects := range []bool{false, true} {
		name := "poll(2)"
		if selects {
			name = "select(2)"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			testTerminalInput(t, selects)
		})
	}
	t.Run("the controlling terminal", func(t *testing.T) {
		t.Parallel()
		tty, err := os.Open("/dev/tty")
		if err != nil {
			t.Skipf("no controlling terminal: %v", err)
		}
		t.Cleanup(func() { _ = tty.Close() })
		in, err := newTerminalInput(t.Context(), tty)
		require.NoError(t, err)
		t.Cleanup(in.close)
		start := time.Now()
		ready, err := in.wait(escTimeout)
		require.NoError(t, err)
		assert.Equal(t, runtime.GOOS == "darwin", in.selects)
		if !ready {
			assert.GreaterOrEqual(t, time.Since(start), escTimeout)
		}
	})
}

func testTerminalInput(t *testing.T, selects bool) {
	pipe := func(t *testing.T) (r, w *os.File) {
		t.Helper()
		r, w, err := os.Pipe()
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = r.Close()
			_ = w.Close()
		})
		return r, w
	}
	input := func(t *testing.T, ctx context.Context, r *os.File) *terminalInput {
		t.Helper()
		in, err := newTerminalInput(ctx, r)
		require.NoError(t, err)
		t.Cleanup(in.close)
		in.selects = selects
		return in
	}
	readBack := func(t *testing.T, r *os.File) string {
		t.Helper()
		got := make(chan string, 1)
		go func() {
			buf := make([]byte, 64)
			n, _ := r.Read(buf)
			got <- string(buf[:n])
		}()
		select {
		case s := <-got:
			return s
		case <-time.After(5 * time.Second):
			t.Fatal("the line typed after the prompt went to a read it left behind")
			return ""
		}
	}
	t.Run("a wait that runs out leaves the input to its next reader", func(t *testing.T) {
		t.Parallel()
		r, w := pipe(t)
		in := input(t, t.Context(), r)
		start := time.Now()
		ready, err := in.wait(escTimeout)
		require.NoError(t, err)
		assert.False(t, ready)
		assert.GreaterOrEqual(t, time.Since(start), escTimeout)
		_, err = w.WriteString("ls\n")
		require.NoError(t, err)
		assert.Equal(t, "ls\n", readBack(t, r))
	})
	t.Run("input ends the wait and is read", func(t *testing.T) {
		t.Parallel()
		r, w := pipe(t)
		in := input(t, t.Context(), r)
		go func() {
			time.Sleep(20 * time.Millisecond)
			_, _ = w.WriteString("a")
		}()
		ready, err := in.wait(0)
		require.NoError(t, err)
		assert.True(t, ready)
		buf := make([]byte, 4)
		n, err := in.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "a", string(buf[:n]))
	})
	t.Run("the input's end ends the wait", func(t *testing.T) {
		t.Parallel()
		r, w := pipe(t)
		in := input(t, t.Context(), r)
		require.NoError(t, w.Close())
		ready, err := in.wait(0)
		require.NoError(t, err)
		assert.True(t, ready)
		_, err = in.Read(make([]byte, 4))
		assert.ErrorIs(t, err, io.EOF)
	})
	t.Run("cancelling the context ends the wait", func(t *testing.T) {
		t.Parallel()
		r, _ := pipe(t)
		ctx, cancel := context.WithCancel(t.Context())
		in := input(t, ctx, r)
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		ready, err := in.wait(0)
		assert.ErrorIs(t, err, context.Canceled)
		assert.False(t, ready)
	})
	t.Run("the prompt leaves nothing reading the terminal", func(t *testing.T) {
		t.Parallel()
		r, w := pipe(t)
		in := input(t, t.Context(), r)
		_, err := w.WriteString("hunter2\r")
		require.NoError(t, err)
		var echo bytes.Buffer
		val, err := readSecretLine(in, &echo, 0, 0)
		require.NoError(t, err)
		assert.Equal(t, "hunter2", val)
		_, err = w.WriteString("ls\n")
		require.NoError(t, err)
		assert.Equal(t, "ls\n", readBack(t, r))
	})
}
