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

package commands

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

// Sentinels driving TestMain modes:
//
//	helperWrapperEnv: act as a RunCommand wrapper — invoke RunCommand with
//	  args=[exe] so it execs this test binary again as a grandchild.
//	helperActiveEnv:  act as the leaf child — exit with the requested code.
const (
	helperWrapperEnv = "GO_PASS_RUN_WRAPPER"
	helperActiveEnv  = "GO_PASS_RUN_HELPER_ACTIVE"
	helperExitEnv    = "GO_PASS_RUN_HELPER_EXIT"
	helperSleepEnv   = "GO_PASS_RUN_HELPER_SLEEP"
)

func TestMain(m *testing.M) {
	if os.Getenv(helperWrapperEnv) != "" {
		// Unset so the grandchild does not recurse into wrapper mode.
		_ = os.Unsetenv(helperWrapperEnv)
		runAsWrapper()
		return // unreachable; runAsWrapper exits
	}
	if os.Getenv(helperActiveEnv) != "" {
		if os.Getenv(helperSleepEnv) != "" {
			// Signal-handling test: announce readiness, then block until a
			// signal kills us with its default disposition (so the wrapper
			// observes a signaled exit, not a normal one).
			_, _ = fmt.Fprintln(os.Stderr, "READY")
			select {}
		}
		code := 0
		if v := os.Getenv(helperExitEnv); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				code = n
			}
		}
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// runAsWrapper invokes RunCommand with args=[exe], so RunCommand execs the
// test binary again as a grandchild. The grandchild's exit code propagates:
// RunCommand calls os.Exit(code), so this wrapper process exits with the same
// code, which the outer test then observes via exec.ExitError.
func runAsWrapper() {
	exe, err := os.Executable()
	if err != nil {
		os.Exit(2)
	}
	cmd := RunCommand()
	cmd.SetArgs([]string{exe})
	cmd.SetContext(context.Background())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err = cmd.Execute()
	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.Code)
	}
	if err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestResolveEnv(t *testing.T) {
	t.Parallel()

	resolver := testhelper.MockResolver{
		Store: map[secrets.ID]string{
			secrets.MustParseID("gh-token"):                "ghp_abc123",
			secrets.MustParseID("myapp/postgres/password"): "s3cr3t",
		},
	}

	t.Run("passthrough when no se:// values", func(t *testing.T) {
		in := []string{"PATH=/usr/bin", "HOME=/home/x", "EMPTY="}
		out, err := resolveEnv(t.Context(), resolver, in)
		require.NoError(t, err)
		assert.Equal(t, in, out)
	})

	t.Run("resolves exact se:// reference", func(t *testing.T) {
		in := []string{"PATH=/usr/bin", "SE_TOKEN=se://gh-token"}
		out, err := resolveEnv(t.Context(), resolver, in)
		require.NoError(t, err)
		assert.Equal(t, []string{"PATH=/usr/bin", "SE_TOKEN=ghp_abc123"}, out)
	})

	t.Run("resolves nested ID", func(t *testing.T) {
		in := []string{"PG_PWD=se://myapp/postgres/password"}
		out, err := resolveEnv(t.Context(), resolver, in)
		require.NoError(t, err)
		assert.Equal(t, []string{"PG_PWD=s3cr3t"}, out)
	})

	t.Run("embedded se:// is left untouched", func(t *testing.T) {
		in := []string{"DSN=postgres://user:se://gh-token@host/db"}
		out, err := resolveEnv(t.Context(), resolver, in)
		require.NoError(t, err)
		assert.Equal(t, in, out)
	})

	t.Run("missing reference hard-fails", func(t *testing.T) {
		in := []string{"X=se://does-not-exist"}
		out, err := resolveEnv(t.Context(), resolver, in)
		require.Error(t, err)
		assert.Nil(t, out)
		assert.Contains(t, err.Error(), "resolving X")
	})

	t.Run("invalid ID hard-fails", func(t *testing.T) {
		in := []string{"X=se://"}
		out, err := resolveEnv(t.Context(), resolver, in)
		require.Error(t, err)
		assert.Nil(t, out)
		assert.Contains(t, err.Error(), "resolving X")
	})

	t.Run("wildcard in reference is rejected", func(t *testing.T) {
		in := []string{"X=se://foo/*"}
		out, err := resolveEnv(t.Context(), resolver, in)
		require.Error(t, err)
		assert.Nil(t, out)
		assert.Contains(t, err.Error(), "resolving X")
	})

	t.Run("multiple refs resolved in order", func(t *testing.T) {
		in := []string{
			"A=se://gh-token",
			"B=plain",
			"C=se://myapp/postgres/password",
		}
		out, err := resolveEnv(t.Context(), resolver, in)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"A=ghp_abc123",
			"B=plain",
			"C=s3cr3t",
		}, out)
	})
}

func TestMergeEnv(t *testing.T) {
	t.Parallel()

	writeFile := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "env")
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		return path
	}

	t.Run("no files returns sorted process env", func(t *testing.T) {
		out, err := mergeEnv([]string{"B=2", "A=1"}, nil)
		require.NoError(t, err)
		assert.Equal(t, []string{"A=1", "B=2"}, out)
	})

	t.Run("file overrides process env", func(t *testing.T) {
		f := writeFile(t, "A=from-file\nC=new\n")
		out, err := mergeEnv([]string{"A=from-process", "B=keep"}, []string{f})
		require.NoError(t, err)
		assert.Equal(t, []string{"A=from-file", "B=keep", "C=new"}, out)
	})

	t.Run("later file overrides earlier file", func(t *testing.T) {
		f1 := writeFile(t, "A=from-file-1\n")
		f2 := writeFile(t, "A=from-file-2\n")
		out, err := mergeEnv(nil, []string{f1, f2})
		require.NoError(t, err)
		assert.Equal(t, []string{"A=from-file-2"}, out)
	})

	t.Run("comments and quoted values", func(t *testing.T) {
		f := writeFile(t, "# this is a comment\nGREETING=\"hello world\"\nQUOTED='no $expand'\n")
		out, err := mergeEnv(nil, []string{f})
		require.NoError(t, err)
		assert.Equal(t, []string{
			"GREETING=hello world",
			"QUOTED=no $expand",
		}, out)
	})

	t.Run("missing file returns error and does not partially apply", func(t *testing.T) {
		f := writeFile(t, "A=present\n")
		out, err := mergeEnv([]string{"B=keep"}, []string{f, "/does/not/exist/.env"})
		require.Error(t, err)
		assert.Nil(t, out)
		assert.Contains(t, err.Error(), "/does/not/exist/.env")
	})

	t.Run("preserves se:// values for downstream resolveEnv", func(t *testing.T) {
		f := writeFile(t, "SE_TOKEN=se://gh-token\nPLAIN=v\n")
		out, err := mergeEnv(nil, []string{f})
		require.NoError(t, err)
		assert.Equal(t, []string{"PLAIN=v", "SE_TOKEN=se://gh-token"}, out)
	})
}

// TestRunCommand covers cobra-level behavior that does not depend on a running
// daemon. Resolution behavior is covered by TestResolveEnv.
func TestRunCommand(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)

	t.Run("no command given returns arg error", func(t *testing.T) {
		cmd := RunCommand()
		cmd.SetArgs([]string{})
		cmd.SetContext(t.Context())
		cmd.SetOut(testWriter{t})
		cmd.SetErr(testWriter{t})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires at least 1 arg")
	})

	t.Run("forwards child exit code", func(t *testing.T) {
		// Spawn a wrapper subprocess that runs RunCommand internally. The
		// wrapper execs a grandchild (this test binary in helper mode) that
		// exits with code 42. The wrapper's env contains no se:// references,
		// so RunCommand never contacts the daemon. RunCommand calls
		// os.Exit(42) on the ExitError, so the wrapper process itself exits
		// 42, which we observe via exec.ExitError.
		sub := exec.CommandContext(t.Context(), exe)
		sub.Env = append(os.Environ(),
			helperWrapperEnv+"=1",
			helperActiveEnv+"=1",
			helperExitEnv+"=42",
		)
		err := sub.Run()
		var exitErr *exec.ExitError
		require.True(t, errors.As(err, &exitErr), "expected ExitError, got %v", err)
		assert.Equal(t, 42, exitErr.ExitCode())
	})

	t.Run("forwards SIGINT and exits 130", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("SIGINT cross-process semantics differ on Windows")
		}

		sub := exec.CommandContext(t.Context(), exe)
		sub.Env = append(os.Environ(),
			helperWrapperEnv+"=1",
			helperActiveEnv+"=1",
			helperSleepEnv+"=1",
		)
		stderr, err := sub.StderrPipe()
		require.NoError(t, err)
		require.NoError(t, sub.Start())

		waitForReady(t, stderr)

		require.NoError(t, sub.Process.Signal(syscall.SIGINT))

		err = sub.Wait()
		var exitErr *exec.ExitError
		require.True(t, errors.As(err, &exitErr), "expected ExitError, got %v", err)
		assert.Equal(t, 130, exitErr.ExitCode())
	})
}

func waitForReady(t *testing.T, r io.Reader) {
	t.Helper()
	scanner := bufio.NewScanner(r)
	done := make(chan bool, 1)
	go func() {
		for scanner.Scan() {
			if scanner.Text() == "READY" {
				done <- true
				return
			}
		}
		done <- false
	}()
	select {
	case ok := <-done:
		require.True(t, ok, "subprocess closed stderr before printing READY")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for READY from subprocess")
	}
	// Drain remaining stderr in the background so the pipe never blocks.
	go func() { _, _ = io.Copy(io.Discard, r) }()
}

// testWriter forwards cobra output to t.Log so it does not leak onto stderr.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
