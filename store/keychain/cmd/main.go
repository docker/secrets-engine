package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path"

	"github.com/spf13/cobra"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/keychain"
	"github.com/docker/secrets-engine/store/mocks"
)

// newCommand creates an example CLI that uses the keychain library
// It supports windows, linux and macOS.
func newCommand() (*cobra.Command, error) {
	kc, err := keychain.New(
		"io.docker.Secrets",
		"docker-example-cli",
		func() *mocks.MockCredential {
			return &mocks.MockCredential{}
		},
	)
	if err != nil {
		return nil, err
	}
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			secrets, err := kc.GetAllMetadata(cmd.Context())
			if errors.Is(err, store.ErrCredentialNotFound) {
				fmt.Println("No Secrets found")
				return nil
			}
			if err != nil {
				return err
			}

			for id, v := range secrets {
				fmt.Printf("\nID: %s\n", id)
				fmt.Printf("\nMetadata: %+v", v.Metadata())
			}
			return nil
		},
	}

	var (
		username string
		password string
	)
	save := &cobra.Command{
		Use:     "store",
		Aliases: []string{"set", "save"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := store.ParseID(path.Join("keystore-cli", username))
			if err != nil {
				return err
			}
			creds := &mocks.MockCredential{
				Username: username,
				Password: password,
			}
			return kc.Save(cmd.Context(), id, creds)
		},
	}
	save.PersistentFlags().StringVar(&username, "username", "", "The secret key")
	save.PersistentFlags().StringVar(&password, "password", "", "The secret value")
	save.MarkFlagsRequiredTogether("username", "password")

	get := &cobra.Command{
		Use:  "get",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := store.ParseID(path.Join("keystore-cli", args[0]))
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
			fmt.Printf("Secret:\nID:%s\nValue:%s\n", id.String(), val)
			return nil
		},
	}

	erase := &cobra.Command{
		Use:     "delete",
		Args:    cobra.ExactArgs(1),
		Aliases: []string{"rm", "remove"},
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := store.ParseID(path.Join("keystore-cli", args[0]))
			if err != nil {
				return err
			}
			return kc.Delete(cmd.Context(), id)
		},
	}
	root := &cobra.Command{}
	root.AddCommand(list, save, get, erase)

	return root, nil
}

func main() {
	ctx := context.Background()
	cmd, err := newCommand()
	if err != nil {
		log.Fatalf("could not create CLI: %v", err)
	}
	cmd.SetContext(ctx)
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
