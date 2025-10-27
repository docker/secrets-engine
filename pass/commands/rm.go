package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

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
			idList, err := validateArgs(args, opts)
			if err != nil {
				return err
			}
			return runRm(cmd.Context(), cmd.OutOrStdout(), kc, idList, opts)
		},
	}
	flags := cmd.Flags()
	flags.BoolVar(&opts.All, "all", false, "Remove all secrets")
	return cmd
}

func validateArgs(args []string, opts rmOpts) ([]store.ID, error) {
	if (len(args) == 0 && !opts.All) || (len(args) > 0 && opts.All) {
		return nil, fmt.Errorf("either provide a secret name or use --all to remove all secrets")
	}
	var result []store.ID
	for _, arg := range args {
		id, err := store.ParseID(arg)
		if err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, nil
}

func runRm(ctx context.Context, out io.Writer, kc store.Store, idList []store.ID, opts rmOpts) error {
	if opts.All && len(idList) == 0 {
		l, err := kc.GetAllMetadata(ctx)
		if err != nil {
			return err
		}
		for k := range l {
			idList = append(idList, k)
		}
	}
	slices.SortFunc(idList, func(a, b store.ID) int { return strings.Compare(a.String(), b.String()) })
	var errs []error
	for _, id := range idList {
		if err := kc.Delete(ctx, id); err != nil {
			errs = append(errs, err)
			fmt.Fprintf(out, "ERR: %s: %s\n", id, err)
			continue
		}
		fmt.Fprintf(out, "RM: %s\n", id)
	}
	return errors.Join(errs...)
}
