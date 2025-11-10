package commands

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	pass "github.com/docker/secrets-engine/pass/store"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/secrets"
)

const setExample = `
# Set a secret:
docker pass set POSTGRES_PASSWORD=my-secret-password

# Or pass the secret via STDIN:
echo my-secret-password > pwd.txt
cat pwd.txt | docker pass set POSTGRES_PASSWORD
`

func SetCommand(kc store.Store) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "set id[=value]",
		Aliases: []string{"store", "save"},
		Short:   "Set a secret",
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
			return kc.Save(cmd.Context(), id, &pass.PassValue{Value: []byte(s.val)})
		},
	}
	return cmd
}

func isNotImplicitReadFromStdinSyntax(args []string) bool {
	return strings.Contains(args[0], "=") || len(args) > 1
}

func secretMappingFromSTDIN(ctx context.Context, reader io.Reader, id string) (*secret, error) {
	data, err := readAllWithContext(ctx, reader)
	if err != nil {
		return nil, err
	}

	return &secret{
		id:  id,
		val: string(data),
	}, nil
}

type secret struct {
	id  string
	val string
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
