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
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"strings"

	"github.com/spf13/cobra"

	pass "github.com/docker/secrets-engine/plugins/pass/store"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/secrets"
)

const setExample = `
### Set a secret:
docker pass set POSTGRES_PASSWORD=my-secret-password

### Or pass the secret via STDIN:
echo my-secret-password > pwd.txt
cat pwd.txt | docker pass set POSTGRES_PASSWORD

### Set a secret with metadata:
docker pass set POSTGRES_PASSWORD=my-secret-password --metadata owner=alice --metadata expiry=2027-03-01

### Or pass a JSON payload with secret and metadata via STDIN:
echo '{"secret":"my-secret-password","metadata":{"owner":"alice"}}' | docker pass set POSTGRES_PASSWORD
`

type setOpts struct {
	metadata []string // raw "key=value" strings from --metadata flag
}

type stdinPayload struct {
	Secret   string            `json:"secret"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func SetCommand(kc store.Store) *cobra.Command {
	opts := setOpts{}
	cmd := &cobra.Command{
		Use:     "set id[=value]",
		Aliases: []string{"store", "save"},
		Short:   "Set a secret",
		Long: `Stores a secret in the local OS keychain. The secret value can be
provided inline (NAME=VALUE) or piped via STDIN.`,
		Example: strings.Trim(setExample, "\n"),
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var s secret
			if isNotImplicitReadFromStdinSyntax(args) {
				va, err := parseArg(args[0])
				if err != nil {
					return err
				}
				s = *va
			} else {
				val, err := secretMappingFromSTDIN(cmd.Context(), cmd.InOrStdin(), args[0])
				if err != nil {
					return err
				}
				s = *val
			}
			id, err := secrets.ParseID(s.id)
			if err != nil {
				return err
			}

			flagMeta, err := parseMetadataFlags(opts.metadata)
			if err != nil {
				return err
			}

			// Merge: start with STDIN JSON metadata, override with flag metadata
			merged := maps.Clone(s.metadata)
			for k, v := range flagMeta {
				if merged == nil {
					merged = make(map[string]string)
				}
				merged[k] = v
			}

			pv := &pass.PassValue{}
			if err := pv.Unmarshal([]byte(s.val)); err != nil {
				return err
			}
			if len(merged) > 0 {
				if err := pv.SetMetadata(merged); err != nil {
					return err
				}
			}
			return kc.Save(cmd.Context(), id, pv)
		},
	}
	flags := cmd.Flags()
	flags.StringArrayVar(&opts.metadata, "metadata", nil, "Non-sensitive key=value metadata (repeatable)")
	return cmd
}

func parseMetadataFlags(raw []string) (map[string]string, error) {
	m := make(map[string]string, len(raw))
	for _, kv := range raw {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("invalid metadata pair (expected key=value): %s", kv)
		}
		m[k] = v
	}
	return m, nil
}

func isNotImplicitReadFromStdinSyntax(args []string) bool {
	return strings.Contains(args[0], "=") || len(args) > 1
}

func secretMappingFromSTDIN(ctx context.Context, reader io.Reader, id string) (*secret, error) {
	data, err := readAllWithContext(ctx, reader)
	if err != nil {
		return nil, err
	}
	defer clear(data)

	var payload stdinPayload
	if err := json.Unmarshal(data, &payload); err == nil && payload.Secret != "" {
		return &secret{id: id, val: payload.Secret, metadata: payload.Metadata}, nil
	}
	return &secret{id: id, val: string(data)}, nil
}

type secret struct {
	id       string
	val      string
	metadata map[string]string
}

func parseArg(arg string) (*secret, error) {
	key, value, found := strings.Cut(arg, "=")
	if !found {
		return nil, fmt.Errorf("no key=value pair: %s", arg)
	}
	return &secret{id: key, val: value}, nil
}

func readAllWithContext(ctx context.Context, r io.Reader) ([]byte, error) {
	var buf []byte
	done := make(chan error, 1)

	go func() {
		data, err := io.ReadAll(r)
		buf = data
		done <- err
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			return nil, err
		}
		return buf, nil
	}
}
