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
	"slices"

	"github.com/spf13/cobra"

	"github.com/docker/secrets-engine/store"
)

func ListCommand(kc store.Store) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List all secrets from local keychain.",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			l, err := kc.GetAllMetadata(cmd.Context())
			if err != nil {
				return err
			}
			var idList []string
			for id := range l {
				idList = append(idList, id.String())
			}
			slices.Sort(idList)
			for _, id := range idList {
				cmd.Println(id)
			}
			return nil
		},
	}
	return cmd
}
