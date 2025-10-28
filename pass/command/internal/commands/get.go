package commands

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/docker/secrets-engine/pass/service"
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
			impl, ok := s.(*service.MyValue)
			if !ok {
				return errors.New("unknown secret type")
			}
			cmd.Printf("ID: %s\nValue: %s\n", id.String(), impl.Value)
			return nil
		},
	}
	return cmd
}
