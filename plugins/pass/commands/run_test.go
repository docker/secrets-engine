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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/client/dockerhub"
	"github.com/docker/secrets-engine/x/api/resolver"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
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
	// helperCheckEnv holds KEY=WANT: the leaf child exits 3 unless its KEY
	// equals WANT, which proves a reference was resolved before exec.
	helperCheckEnv = "GO_PASS_RUN_HELPER_CHECK"
	// helperSocketEnv makes the wrapper target this socket with no request
	// timeout, forcing the preflight ping to run.
	helperSocketEnv = "GO_PASS_RUN_HELPER_SOCKET"
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
		if v := os.Getenv(helperCheckEnv); v != "" {
			key, want, _ := strings.Cut(v, "=")
			if os.Getenv(key) != want {
				os.Exit(3)
			}
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
	// bounded timeout skips the preflight ping; no engine needed
	ropts := []RunOption{WithTimeout(time.Second)}
	if socket := os.Getenv(helperSocketEnv); socket != "" {
		ropts = []RunOption{WithSocketPath(socket)}
	}
	cmd, err := RunCommand(ropts...)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
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
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

func TestParseEnv(t *testing.T) {
	t.Parallel()

	t.Run("plain values carry no pattern", func(t *testing.T) {
		vars, err := parseEnv([]string{"PATH=/usr/bin", "HOME=/home/x", "EMPTY="})
		require.NoError(t, err)
		assert.Equal(t, []envVar{
			{key: "PATH", value: "/usr/bin"},
			{key: "HOME", value: "/home/x"},
			{key: "EMPTY"},
		}, vars)
	})

	t.Run("se:// values carry their pattern and keep the original value", func(t *testing.T) {
		vars, err := parseEnv([]string{"SE_TOKEN=se://gh-token", "B=plain", "PG_PWD=se://myapp/postgres/password"})
		require.NoError(t, err)
		assert.Equal(t, []envVar{
			{key: "SE_TOKEN", value: "se://gh-token", pattern: secrets.MustParsePattern("gh-token")},
			{key: "B", value: "plain"},
			{key: "PG_PWD", value: "se://myapp/postgres/password", pattern: secrets.MustParsePattern("myapp/postgres/password")},
		}, vars)
	})

	t.Run("embedded se:// is left untouched", func(t *testing.T) {
		vars, err := parseEnv([]string{"DSN=postgres://user:se://gh-token@host/db"})
		require.NoError(t, err)
		assert.Equal(t, []envVar{{key: "DSN", value: "postgres://user:se://gh-token@host/db"}}, vars)
	})

	t.Run("invalid ID hard-fails", func(t *testing.T) {
		vars, err := parseEnv([]string{"X=se://"})
		require.Error(t, err)
		assert.Nil(t, vars)
		assert.ErrorContains(t, err, "resolving X")
	})

	t.Run("wildcard in reference is rejected", func(t *testing.T) {
		vars, err := parseEnv([]string{"X=se://foo/*"})
		require.Error(t, err)
		assert.Nil(t, vars)
		assert.ErrorContains(t, err, "resolving X")
	})
}

// mustParseEnv parses env, failing the test on an invalid reference.
func mustParseEnv(t *testing.T, env []string) []envVar {
	t.Helper()
	vars, err := parseEnv(env)
	require.NoError(t, err)
	return vars
}

func TestResolveEnv(t *testing.T) {
	t.Parallel()

	mock := testhelper.MockResolver{
		Store: map[secrets.ID]string{
			secrets.MustParseID("gh-token"):                "ghp_abc123",
			secrets.MustParseID("myapp/postgres/password"): "s3cr3t",
		},
	}

	t.Run("passthrough when no se:// values", func(t *testing.T) {
		in := []string{"PATH=/usr/bin", "HOME=/home/x", "EMPTY="}
		out, err := resolveEnv(t.Context(), mock, mustParseEnv(t, in))
		require.NoError(t, err)
		assert.Equal(t, in, out)
	})

	t.Run("resolves exact se:// reference", func(t *testing.T) {
		in := []string{"PATH=/usr/bin", "SE_TOKEN=se://gh-token"}
		out, err := resolveEnv(t.Context(), mock, mustParseEnv(t, in))
		require.NoError(t, err)
		assert.Equal(t, []string{"PATH=/usr/bin", "SE_TOKEN=ghp_abc123"}, out)
	})

	t.Run("resolves nested ID", func(t *testing.T) {
		in := []string{"PG_PWD=se://myapp/postgres/password"}
		out, err := resolveEnv(t.Context(), mock, mustParseEnv(t, in))
		require.NoError(t, err)
		assert.Equal(t, []string{"PG_PWD=s3cr3t"}, out)
	})

	t.Run("missing reference hard-fails", func(t *testing.T) {
		in := []string{"X=se://does-not-exist"}
		out, err := resolveEnv(t.Context(), mock, mustParseEnv(t, in))
		require.ErrorIs(t, err, secrets.ErrNotFound)
		assert.Nil(t, out)
		assert.ErrorContains(t, err, "resolving X")
	})

	t.Run("multiple refs resolved in order", func(t *testing.T) {
		in := []string{
			"A=se://gh-token",
			"B=plain",
			"C=se://myapp/postgres/password",
		}
		out, err := resolveEnv(t.Context(), mock, mustParseEnv(t, in))
		require.NoError(t, err)
		assert.Equal(t, []string{
			"A=ghp_abc123",
			"B=plain",
			"C=s3cr3t",
		}, out)
	})
}

func writeEnvFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "env")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestMergeEnv(t *testing.T) {
	t.Parallel()

	t.Run("no files returns sorted process env", func(t *testing.T) {
		out, err := mergeEnv([]string{"B=2", "A=1"}, nil)
		require.NoError(t, err)
		assert.Equal(t, []string{"A=1", "B=2"}, out)
	})

	t.Run("file overrides process env", func(t *testing.T) {
		f := writeEnvFile(t, "A=from-file\nC=new\n")
		out, err := mergeEnv([]string{"A=from-process", "B=keep"}, []string{f})
		require.NoError(t, err)
		assert.Equal(t, []string{"A=from-file", "B=keep", "C=new"}, out)
	})

	t.Run("later file overrides earlier file", func(t *testing.T) {
		f1 := writeEnvFile(t, "A=from-file-1\n")
		f2 := writeEnvFile(t, "A=from-file-2\n")
		out, err := mergeEnv(nil, []string{f1, f2})
		require.NoError(t, err)
		assert.Equal(t, []string{"A=from-file-2"}, out)
	})

	t.Run("comments and quoted values", func(t *testing.T) {
		f := writeEnvFile(t, "# this is a comment\nGREETING=\"hello world\"\nQUOTED='no $expand'\n")
		out, err := mergeEnv(nil, []string{f})
		require.NoError(t, err)
		assert.Equal(t, []string{
			"GREETING=hello world",
			"QUOTED=no $expand",
		}, out)
	})

	t.Run("missing file returns error and does not partially apply", func(t *testing.T) {
		f := writeEnvFile(t, "A=present\n")
		out, err := mergeEnv([]string{"B=keep"}, []string{f, "/does/not/exist/.env"})
		require.Error(t, err)
		assert.Nil(t, out)
		assert.Contains(t, err.Error(), "/does/not/exist/.env")
	})

	t.Run("preserves se:// values for downstream parseEnv", func(t *testing.T) {
		f := writeEnvFile(t, "SE_TOKEN=se://gh-token\nPLAIN=v\n")
		out, err := mergeEnv(nil, []string{f})
		require.NoError(t, err)
		assert.Equal(t, []string{"PLAIN=v", "SE_TOKEN=se://gh-token"}, out)
	})
}

func TestRunCommandOptions(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		options []RunOption
		wantErr string
	}{
		{name: "defaults"},
		{
			name: "explicit options",
			options: []RunOption{
				WithSocketPath("/tmp/secrets-engine.sock"),
				WithTimeout(time.Second),
				WithResponseTimeout(time.Second),
			},
		},
		{
			name:    "zero disables timeouts",
			options: []RunOption{WithTimeout(0), WithResponseTimeout(0)},
		},
		{
			name:    "empty socket path",
			options: []RunOption{WithSocketPath("")},
			wantErr: "no path provided",
		},
		{
			name:    "negative request timeout",
			options: []RunOption{WithTimeout(-time.Second)},
			wantErr: "request timeout duration cannot be negative",
		},
		{
			name:    "negative response timeout",
			options: []RunOption{WithResponseTimeout(-time.Second)},
			wantErr: "response timeout duration cannot be negative",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd, err := RunCommand(tt.options...)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				assert.Nil(t, cmd)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, cmd)
		})
	}

	t.Run("stops at the first option error", func(t *testing.T) {
		t.Parallel()
		optionErr := errors.New("invalid option")
		laterOptionCalled := false
		cmd, err := RunCommand(
			func(*runOpts) error { return optionErr },
			func(*runOpts) error {
				laterOptionCalled = true
				return nil
			},
		)
		require.ErrorIs(t, err, optionErr)
		assert.Nil(t, cmd)
		assert.False(t, laterOptionCalled)
	})
}

// TestRunCommand covers cobra-level behavior against a mock engine or none.
// TestParseEnv and TestResolveEnv cover the details.
func TestRunCommand(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)

	t.Run("no command given returns arg error", func(t *testing.T) {
		cmd, err := RunCommand()
		require.NoError(t, err)
		cmd.SetArgs([]string{})
		cmd.SetContext(t.Context())
		cmd.SetOut(testWriter{t})
		cmd.SetErr(testWriter{t})
		err = cmd.Execute()
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

	t.Run("preflight ping fails fast on a dead socket", func(t *testing.T) {
		sub := exec.CommandContext(t.Context(), exe)
		sub.Env = append(os.Environ(),
			helperWrapperEnv+"=1",
			helperActiveEnv+"=1",
			helperExitEnv+"=0",
			helperSocketEnv+"="+filepath.Join(t.TempDir(), "dead.sock"),
		)
		var stderr bytes.Buffer
		sub.Stderr = &stderr
		err := sub.Run()
		var exitErr *exec.ExitError
		require.True(t, errors.As(err, &exitErr), "expected ExitError, got %v", err)
		assert.Equal(t, 2, exitErr.ExitCode())
		assert.Contains(t, stderr.String(), "preflight ping")
	})

	t.Run("authorizes every reference before resolving", func(t *testing.T) {
		engine := &mockEngine{allow: true, store: map[secrets.ID]string{
			secrets.MustParseID("gh-token"): "ghp_abc123",
		}}
		// The child is this binary in leaf mode: it exits 3 unless SE_TOKEN
		// arrives resolved. Files override the process env, so the env-file
		// drives the child without touching the test process.
		envFile := writeEnvFile(t, "SE_TOKEN=se://gh-token\n"+
			helperActiveEnv+"=1\n"+
			helperCheckEnv+"=SE_TOKEN=ghp_abc123\n")
		cmd, err := RunCommand(WithTimeout(time.Second), WithSocketPath(engine.serve(t)))
		require.NoError(t, err)
		cmd.SetArgs([]string{"--env-file", envFile, exe})
		cmd.SetContext(t.Context())
		cmd.SetOut(testWriter{t})
		cmd.SetErr(testWriter{t})
		require.NoError(t, cmd.Execute())
		assert.Equal(t, []string{"authorize gh-token", "resolve gh-token"}, engine.recorded())
	})

	t.Run("a denied authorization stops before resolving", func(t *testing.T) {
		engine := &mockEngine{store: map[secrets.ID]string{
			secrets.MustParseID("gh-token"): "ghp_abc123",
		}}
		envFile := writeEnvFile(t, "SE_TOKEN=se://gh-token\n"+helperActiveEnv+"=1\n")
		cmd, err := RunCommand(WithTimeout(time.Second), WithSocketPath(engine.serve(t)))
		require.NoError(t, err)
		cmd.SetArgs([]string{"--env-file", envFile, exe})
		cmd.SetContext(t.Context())
		cmd.SetOut(testWriter{t})
		cmd.SetErr(testWriter{t})
		err = cmd.Execute()
		require.ErrorIs(t, err, client.ErrAccessDenied)
		assert.ErrorContains(t, err, "authorizing: access denied")
		assert.Equal(t, []string{"authorize gh-token"}, engine.recorded())
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

type mockEngine struct {
	allow bool
	store map[secrets.ID]string

	mu    sync.Mutex
	calls []string
}

func (e *mockEngine) Authorize(_ context.Context, patterns ...secrets.Pattern) (secrets.AuthorizeResponse, error) {
	names := make([]string, 0, len(patterns))
	for _, p := range patterns {
		names = append(names, p.String())
	}
	e.record("authorize " + strings.Join(names, ","))
	return secrets.AuthorizeResponse{Allow: e.allow}, nil
}

func (e *mockEngine) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	e.record("resolve " + pattern.String())
	return testhelper.MockResolver{Store: e.store}.GetSecrets(ctx, pattern)
}

func (e *mockEngine) record(call string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, call)
}

func (e *mockEngine) recorded() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.calls)
}

// serve starts the engine on a fresh socket and returns the socket path.
func (e *mockEngine) serve(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(resolverv1connect.NewAuthorizerServiceHandler(resolver.NewAuthorizerHandler(e)))
	mux.Handle(resolverv1connect.NewResolverServiceHandler(resolver.NewResolverHandler(e)))
	socket := testhelper.RandomShortSocketName()
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return socket
}

// pingClient adapts a Version func to client.Client.
type pingClient struct {
	testhelper.MockResolver
	ping func(context.Context) (client.DaemonVersion, error)
}

func (p pingClient) Version(ctx context.Context) (client.DaemonVersion, error) {
	return p.ping(ctx)
}

func (p pingClient) Authorize(context.Context, ...secrets.Pattern) (secrets.AuthorizeResponse, error) {
	return secrets.AuthorizeResponse{Allow: true}, nil
}

func (pingClient) HubAuth(...dockerhub.Option) dockerhub.ClientAuth {
	return nil
}

func TestPreflightPing(t *testing.T) {
	t.Parallel()

	t.Run("passes when the engine responds", func(t *testing.T) {
		t.Parallel()
		c := pingClient{ping: func(_ context.Context) (client.DaemonVersion, error) {
			return client.DaemonVersion{}, nil
		}}
		require.NoError(t, preflightPing(t.Context(), c, time.Second))
	})

	t.Run("fails when the engine is unreachable", func(t *testing.T) {
		t.Parallel()
		engineErr := errors.New("connection refused")
		c := pingClient{ping: func(_ context.Context) (client.DaemonVersion, error) {
			return client.DaemonVersion{}, engineErr
		}}
		err := preflightPing(t.Context(), c, time.Second)
		require.Error(t, err)
		assert.ErrorContains(t, err, "preflight ping")
		assert.ErrorIs(t, err, engineErr)
		assert.ErrorIs(t, err, client.ErrSecretsEngineNotAvailable)
	})

	t.Run("gives up after the timeout when the engine hangs", func(t *testing.T) {
		t.Parallel()
		c := pingClient{ping: func(ctx context.Context) (client.DaemonVersion, error) {
			<-ctx.Done()
			return client.DaemonVersion{}, ctx.Err()
		}}
		// Watchdog: if preflightPing loses its own deadline, the elapsed
		// assertion fails instead of the package hanging.
		watchdogCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		start := time.Now()
		err := preflightPing(watchdogCtx, c, 50*time.Millisecond)
		require.Error(t, err)
		require.Less(t, time.Since(start), 2*time.Second)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.ErrorIs(t, err, client.ErrSecretsEngineNotAvailable)
	})
}

// testWriter forwards cobra output to t.Log so it does not leak onto stderr.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
