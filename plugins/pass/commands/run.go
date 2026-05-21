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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

const sePrefix = "se://"

const runExample = `
### Run a command with one secret in its environment:
SE_TOKEN=se://gh-token docker pass run -- gh repo list

### Multiple references:
DB_PASSWORD=se://myapp/postgres/password \
API_KEY=se://myapp/anthropic/api-key \
  docker pass run -- ./my-binary
`

func RunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run -- CMD [ARGS...]",
		Short: "Run a command with se:// environment references resolved.",
		Long: `Scans the current environment for variables whose value is exactly se://NAME.
Each reference is resolved through the secrets-engine daemon and the resolved
value is passed to the child process. The child inherits stdin, stdout, and
stderr.

Requires the secrets-engine daemon (Docker Desktop) to be running.

If any reference cannot be resolved, the command fails before the child is
started and exits non-zero.`,
		Example: strings.Trim(runExample, "\n"),
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client.New(client.WithSocketPath(api.DefaultSocketPath()))
			if err != nil {
				return err
			}

			env, err := resolveEnv(cmd.Context(), c, os.Environ())
			if err != nil {
				return err
			}

			child := exec.CommandContext(cmd.Context(), args[0], args[1:]...)
			child.Env = env
			child.Stdin = os.Stdin
			child.Stdout = os.Stdout
			child.Stderr = os.Stderr

			if err := child.Run(); err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					os.Exit(exitErr.ExitCode())
				}
				return err
			}
			return nil
		},
	}
	return cmd
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
