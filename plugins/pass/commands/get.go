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
	"io"
	"strings"

	"github.com/spf13/cobra"

	pass "github.com/docker/secrets-engine/plugins/pass/store"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/secrets"
)

//go:embed get_example.md
var getExample string

//go:embed get_long.md
var getLong string

const maskedValue = "**********"

func GetCommand(options ...ClientOption) (*cobra.Command, error) {
	clientOpts, err := parseClientOptions(options...)
	if err != nil {
		return nil, err
	}
	var reveal bool
	cmd := &cobra.Command{
		Use:     "get NAME",
		Args:    cobra.ExactArgs(1),
		Short:   "Get a secret from a keystore.",
		Long:    strings.Trim(getLong, "\n"),
		Example: strings.Trim(getExample, "\n"),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := store.ParseID(args[0])
			if err != nil {
				return err
			}
			kc, err := StoreFrom(cmd.Context())
			if err != nil {
				return err
			}
			s, err := kc.Get(cmd.Context(), id)
			if err != nil {
				return err
			}
			pv, ok := s.(*pass.PassValue)
			if !ok {
				return errors.New("unknown secret type")
			}
			if !reveal {
				return printSecret(cmd.OutOrStdout(), id, []byte(maskedValue))
			}
			if err := authorizeReveal(cmd.Context(), clientOpts, id); err != nil {
				return err
			}
			value, err := pv.Marshal()
			if err != nil {
				return err
			}
			defer clear(value)
			return printSecret(cmd.OutOrStdout(), id, value)
		},
	}
	cmd.Flags().BoolVar(&reveal, "reveal", false, "Show the secret value in plaintext")
	return wrapKeychainErrors(cmd), nil
}

func authorizeReveal(ctx context.Context, opts clientOpts, id store.ID) error {
	pattern, err := secrets.ParsePattern(id.String())
	if err != nil {
		return err
	}
	c, err := newClient(opts)
	if err != nil {
		return err
	}
	if opts.isUnbound() {
		if err := preflightPing(ctx, c, defaultPreflightPingTimeout); err != nil {
			return err
		}
	}
	return authorize(ctx, c, pattern)
}

func printSecret(w io.Writer, id store.ID, value []byte) error {
	_, err := fmt.Fprintf(w, "ID: %s\nValue: %s\n", id, value)
	return err
}
