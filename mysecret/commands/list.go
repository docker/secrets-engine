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
				idList = append(idList, id)
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
