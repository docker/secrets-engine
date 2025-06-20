package main

import (
	"context"
	"fmt"
	"log"
	"path"

	"github.com/docker/secrets-engine/keychain"
	"github.com/docker/secrets-engine/keychain/mocks"
	"github.com/spf13/cobra"
)

func NewCommand() (*cobra.Command, error) {
	kc, err := keychain.New(
		func() *mocks.MockCredential {
			return &mocks.MockCredential{}
		},
		keychain.WithKeyPrefix[*mocks.MockCredential]("cli"),
	)
	if err != nil {
		return nil, err
	}
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			secrets, err := kc.GetAll(cmd.Context())
			if err != nil {
				return err
			}
			if len(secrets) == 0 {
				fmt.Println("No Secrets found")
				return nil
			}
			for k, v := range secrets {
				vv, err := v.Marshal()
				if err != nil {
					return err
				}
				fmt.Printf("\nID: %s\nValues: %s\n", k, vv)
			}
			return nil
		},
	}

	var (
		username string
		password string
	)
	store := &cobra.Command{
		Use:     "store",
		Aliases: []string{"set"},
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := keychain.ParseID(path.Join("keystore-cli", username))
			if err != nil {
				return err
			}
			creds := &mocks.MockCredential{
				Username: username,
				Password: password,
			}
			return kc.Store(cmd.Context(), id, creds)
		},
	}
	store.PersistentFlags().StringVar(&username, "username", "", "The secret key")
	store.PersistentFlags().StringVar(&password, "password", "", "The secret value")
	store.MarkFlagsRequiredTogether("username", "password")

	retrieve := &cobra.Command{
		Use:  "get",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := keychain.ParseID(path.Join("keystore-cli", args[0]))
			if err != nil {
				return err
			}
			secret, err := kc.Get(cmd.Context(), id)
			if err != nil {
				return err
			}
			val, err := secret.Marshal()
			if err != nil {
				return err
			}
			fmt.Printf("Secret:\nID:%s\nValues:%s\n", id.String(), val)
			return nil
		},
	}

	erase := &cobra.Command{
		Use:     "erase",
		Args:    cobra.ExactArgs(1),
		Aliases: []string{"rm", "remove"},
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := keychain.ParseID(path.Join("keystore-cli", args[0]))
			if err != nil {
				return err
			}
			return kc.Erase(cmd.Context(), id)
		},
	}
	root := &cobra.Command{}
	root.AddCommand(list, store, retrieve, erase)

	return root, nil
}

func main() {
	ctx := context.Background()
	cmd, err := NewCommand()
	if err != nil {
		log.Fatalf("could not create CLI: %v", err)
	}
	cmd.SetContext(ctx)
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
