package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/spf13/cobra"

	"github.com/docker/secrets-engine/store"
)

type rmOpts struct {
	All bool
}

func RmCommand(kc store.Store) *cobra.Command {
	opts := rmOpts{}
	cmd := &cobra.Command{
		Use:     "rm name1 name2 ...",
		Aliases: []string{"delete", "erase", "remove"},
		Short:   "Remove secrets from local keychain.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateArgs(args, opts); err != nil {
				return err
			}
			return runRm(cmd.Context(), cmd.OutOrStdout(), kc, args, opts)
		},
	}
	flags := cmd.Flags()
	flags.BoolVar(&opts.All, "all", false, "Remove all secrets")
	return cmd
}

func validateArgs(args []string, opts rmOpts) error {
	if (len(args) == 0 && !opts.All) || (len(args) > 0 && opts.All) {
		return fmt.Errorf("either provide a secret name or use --all to remove all secrets")
	}
	return nil
}

func runRm(ctx context.Context, out io.Writer, kc store.Store, names []string, opts rmOpts) error {
	if opts.All && len(names) == 0 {
		l, err := kc.GetAllMetadata(ctx)
		if err != nil {
			return err
		}
		for k := range l {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	var errs []error
	for _, name := range names {
		id, err := store.ParseID(name)
		if err != nil {
			fmt.Fprintf(out, "ERR: %s: invalid ID\n", name)
			errs = append(errs, err)
			continue
		}
		if err := kc.Delete(ctx, id); err != nil {
			errs = append(errs, err)
			fmt.Fprintf(out, "ERR: %s: %s\n", name, err)
			continue
		}
		fmt.Fprintf(out, "RM: %s\n", name)
	}
	return errors.Join(errs...)
}
