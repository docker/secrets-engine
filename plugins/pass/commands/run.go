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
	"context"
	_ "embed"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

const sePrefix = "se://"

const defaultPreflightPingTimeout = 3 * time.Second

// ExitCodeError is returned when the child process exits non-zero, letting the
// OTel span wrapper finish before the process exits.
type ExitCodeError struct {
	Code int
}

func (e *ExitCodeError) Error() string {
	return fmt.Sprintf("child exited with code %d", e.Code)
}

//go:embed run_example.md
var runExample string

//go:embed run_long.md
var runLong string

type runOpts struct {
	envFiles        []string
	timeout         *time.Duration
	responseTimeout *time.Duration
	socketPath      string
}

type RunOption func(*runOpts)

// WithTimeout sets the client request timeout; 0 disables it.
func WithTimeout(timeout time.Duration) RunOption {
	return func(o *runOpts) {
		o.timeout = &timeout
	}
}

// WithResponseTimeout sets the client response header timeout; 0 disables it.
func WithResponseTimeout(responseTimeout time.Duration) RunOption {
	return func(o *runOpts) {
		o.responseTimeout = &responseTimeout
	}
}

// WithSocketPath overrides the engine socket path; empty means the default.
func WithSocketPath(socketPath string) RunOption {
	return func(o *runOpts) {
		o.socketPath = socketPath
	}
}

func RunCommand(options ...RunOption) *cobra.Command {
	opts := runOpts{}
	for _, o := range options {
		o(&opts)
	}
	cmd := &cobra.Command{
		Use:     "run -- CMD [ARGS...]",
		Short:   "Run a command with `se://` environment references resolved.",
		Long:    strings.Trim(runLong, "\n"),
		Example: strings.Trim(runExample, "\n"),
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			merged, err := mergeEnv(os.Environ(), opts.envFiles)
			if err != nil {
				return err
			}

			vars, err := parseEnv(merged)
			if err != nil {
				return err
			}

			c, err := newRunClient(opts)
			if err != nil {
				return err
			}

			if opts.timeout == nil || *opts.timeout == 0 {
				if err := preflightPing(cmd.Context(), c, defaultPreflightPingTimeout); err != nil {
					return err
				}
			}

			if err := authorizeEnv(cmd.Context(), c, vars); err != nil {
				return err
			}

			env, err := resolveEnv(cmd.Context(), c, vars)
			if err != nil {
				return err
			}

			// No CommandContext: cobra's ctx cancellation would SIGKILL the
			// child out from under the signal forwarder.
			child := exec.Command(args[0], args[1:]...)
			child.Env = env
			child.Stdin = os.Stdin
			child.Stdout = os.Stdout
			child.Stderr = os.Stderr
			configureChildProcGroup(child) // own process group; Ctrl-C goes to us only

			// Install before Start to avoid orphaning the child if a signal
			// arrives between fork and the forwarder goroutine.
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, forwardableSignals()...)
			defer signal.Stop(sigCh)

			if err := child.Start(); err != nil {
				return fmt.Errorf("starting child: %w", err)
			}

			done := make(chan struct{})
			go func() {
				for {
					select {
					case sig := <-sigCh:
						_ = signalChild(child, sig)
					case <-done:
						return
					}
				}
			}()

			waitErr := child.Wait()
			close(done)

			if waitErr != nil {
				var exitErr *exec.ExitError
				if errors.As(waitErr, &exitErr) {
					return &ExitCodeError{Code: childExitCode(exitErr.ProcessState)}
				}
				return waitErr
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&opts.envFiles, "env-file", nil,
		"Read environment variables from a dotenv-formatted file. Repeatable; later files override earlier files and the process environment.")
	return cmd
}

func mergeEnv(processEnv, files []string) ([]string, error) {
	merged := make(map[string]string, len(processEnv))
	for _, kv := range processEnv {
		if k, v, ok := strings.Cut(kv, "="); ok {
			merged[k] = v
		}
	}
	for _, f := range files {
		parsed, err := godotenv.Read(f)
		if err != nil {
			return nil, fmt.Errorf("reading env-file %s: %w", f, err)
		}
		maps.Copy(merged, parsed)
	}
	out := make([]string, 0, len(merged))
	for k, v := range merged {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out, nil
}

func newRunClient(opts runOpts) (client.Client, error) {
	socketPath := opts.socketPath
	if socketPath == "" {
		socketPath = api.DefaultSocketPath()
	}
	copts := []client.Option{client.WithSocketPath(socketPath)}
	if opts.timeout != nil {
		copts = append(copts, client.WithTimeout(*opts.timeout))
	}
	if opts.responseTimeout != nil {
		copts = append(copts, client.WithResponseTimeout(*opts.responseTimeout))
	}
	return client.New(copts...)
}

// preflightPing fails fast when the engine is unreachable, so an unbounded
// client cannot hang resolution indefinitely.
func preflightPing(ctx context.Context, c client.Client, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := c.Version(ctx); err != nil {
		if !errors.Is(err, client.ErrSecretsEngineNotAvailable) {
			err = fmt.Errorf("%w: %w", client.ErrSecretsEngineNotAvailable, err)
		}
		return fmt.Errorf("preflight ping: %w", err)
	}
	return nil
}

type envVar struct {
	key     string
	value   string
	pattern secrets.Pattern
}

func parseEnv(env []string) ([]envVar, error) {
	vars := make([]envVar, 0, len(env))
	for _, kv := range env {
		key, value, _ := strings.Cut(kv, "=")
		v := envVar{key: key, value: value}
		if rawSeRef, ok := strings.CutPrefix(value, sePrefix); ok {
			// ParseID rejects wildcards before ParsePattern broadens the lookup.
			if _, err := secrets.ParseID(rawSeRef); err != nil {
				return nil, fmt.Errorf("resolving %s: %w", key, err)
			}
			pattern, err := secrets.ParsePattern(rawSeRef)
			if err != nil {
				return nil, fmt.Errorf("resolving %s: %w", key, err)
			}
			v.pattern = pattern
		}
		vars = append(vars, v)
	}
	return vars, nil
}

func authorizeEnv(ctx context.Context, a secrets.Authorizer, vars []envVar) error {
	var patterns []secrets.Pattern
	for _, v := range vars {
		if v.pattern == nil {
			continue
		}
		patterns = append(patterns, v.pattern)
	}
	if len(patterns) == 0 {
		return nil
	}
	resp, err := a.Authorize(ctx, patterns...)
	if err != nil {
		return fmt.Errorf("authorizing: %w", err)
	}
	if !resp.Allow {
		return fmt.Errorf("authorizing: %w", secrets.ErrAccessDenied)
	}
	return nil
}

func resolveEnv(ctx context.Context, r secrets.Resolver, vars []envVar) ([]string, error) {
	var out []string
	for _, v := range vars {
		value, err := resolveVar(ctx, r, v)
		if err != nil {
			return nil, err
		}
		out = append(out, v.key+"="+value)
	}
	return out, nil
}

func resolveVar(ctx context.Context, r secrets.Resolver, v envVar) (string, error) {
	if v.pattern == nil {
		return v.value, nil
	}
	envs, err := r.GetSecrets(ctx, v.pattern)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", v.key, err)
	}
	if len(envs) == 0 {
		return "", fmt.Errorf("resolving %s: %w", v.key, secrets.ErrNotFound)
	}
	if len(envs) > 1 {
		return "", fmt.Errorf("resolving %s: %d secrets matched %s", v.key, len(envs), v.pattern)
	}
	return string(envs[0].Value), nil
}
