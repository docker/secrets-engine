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
	"errors"

	"github.com/spf13/cobra"

	pass "github.com/docker/secrets-engine/plugins/pass/store"
	"github.com/docker/secrets-engine/store"
)

func GetCommand(kc store.Store) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Args:  cobra.ExactArgs(1),
		Short: "Get a secret from a keystore.",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := store.ParseID(args[0])
			if err != nil {
				return err
			}
			s, err := kc.Get(cmd.Context(), id)
			if err != nil {
				return err
			}
			_, ok := s.(*pass.PassValue)
			if !ok {
				return errors.New("unknown secret type")
			}
			cmd.Printf("ID: %s\nValue: %s\n", id.String(), "**********")
			return nil
		},
	}
	return cmd
}
