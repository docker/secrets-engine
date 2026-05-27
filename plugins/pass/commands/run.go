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

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

const sePrefix = "se://"

// ExitCodeError is returned from RunCommand when the executed child process
// terminated with a non-zero status. It carries the exit code the wrapper
// should exit with. Returning this instead of calling os.Exit directly lets
// the surrounding OTel span wrapper finish recording metrics and span data
// before the process exits.
type ExitCodeError struct {
	Code int
}

func (e *ExitCodeError) Error() string {
	return fmt.Sprintf("child exited with code %d", e.Code)
}

//go:embed run_example.md
var runExample string

type runOpts struct {
	envFiles []string
}

func RunCommand() *cobra.Command {
	opts := runOpts{}
	cmd := &cobra.Command{
		Use:   "run -- CMD [ARGS...]",
		Short: "Run a command with `se://` environment references resolved.",
		Long: "Scans the current environment (plus any `--env-file` inputs) for variables\n" +
			"whose value is exactly `se://<ID|pattern>`. Each reference is resolved through the\n" +
			"secrets-engine daemon and the resolved value is passed to the child process.\n" +
			"The child inherits stdin, stdout, and stderr.\n" +
			"\n" +
			"Requires the secrets-engine daemon (Docker Desktop) to be running.\n" +
			"\n" +
			"If any reference cannot be resolved, the command fails before the child is\n" +
			"started and exits non-zero.",
		Example: strings.Trim(runExample, "\n"),
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			merged, err := mergeEnv(os.Environ(), opts.envFiles)
			if err != nil {
				return err
			}

			c, err := client.New(client.WithSocketPath(api.DefaultSocketPath()))
			if err != nil {
				return err
			}

			env, err := resolveEnv(cmd.Context(), c, merged)
			if err != nil {
				return err
			}

			// No CommandContext: the signal forwarder owns the child's
			// lifecycle. Tying the child to cmd.Context() would let cobra's
			// ctx cancellation SIGKILL the child out from under the forwarder.
			child := exec.Command(args[0], args[1:]...)
			child.Env = env
			child.Stdin = os.Stdin
			child.Stdout = os.Stdout
			child.Stderr = os.Stderr
			// Isolate the child in its own process group so that
			// terminal-generated signals (Ctrl-C) are delivered to us alone;
			// the forwarder is then the sole path that reaches the child.
			configureChildProcGroup(child)

			// Install the signal handler before Start so a signal arriving in
			// the window between fork and the forwarder goroutine cannot kill
			// the parent and orphan the child.
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

// mergeEnv folds the process environment and any --env-file inputs into a
// single deterministic KEY=VALUE slice. Precedence: process env first, then
// each file in order; later entries override earlier ones.
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

func resolveEnv(ctx context.Context, r secrets.Resolver, env []string) ([]string, error) {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		key, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(value, sePrefix) {
			out = append(out, kv)
			continue
		}
		resolved, err := resolveRef(ctx, r, key, value)
		if err != nil {
			return nil, err
		}
		out = append(out, key+"="+resolved)
	}
	return out, nil
}

func resolveRef(ctx context.Context, r secrets.Resolver, key, value string) (string, error) {
	name := strings.TrimPrefix(value, sePrefix)
	// Validate as an ID first so wildcards in the reference are rejected
	// instead of silently broadening the lookup.
	if _, err := secrets.ParseID(name); err != nil {
		return "", fmt.Errorf("resolving %s: %w", key, err)
	}
	pattern, err := secrets.ParsePattern(name)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", key, err)
	}
	envs, err := r.GetSecrets(ctx, pattern)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", key, err)
	}
	if len(envs) == 0 {
		return "", fmt.Errorf("resolving %s: %w", key, secrets.ErrNotFound)
	}
	if len(envs) > 1 {
		return "", fmt.Errorf("resolving %s: %d secrets matched %s", key, len(envs), name)
	}
	return string(envs[0].Value), nil
}
