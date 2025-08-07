package commands

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/mysecret/service"

	"github.com/spf13/cobra"
)

const setExample = `
# Set a secret:
docker mysecret set POSTGRES_PASSWORD=my-secret-password

# Or pass the secret via STDIN:
echo my-secret-password > pwd.txt
cat pwd.txt | docker mysecret set POSTGRES_PASSWORD
`

func SetCommand() *cobra.Command {
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
				val, err := secretMappingFromSTDIN(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				s = *val
			}
			id, err := secrets.ParseID(s.id)
			if err != nil {
				return err
			}
			kc, err := service.KCService()
			if err != nil {
				return err
			}
			return kc.Save(cmd.Context(), id, &service.MyValue{Value: []byte(s.val)})
		},
	}
	return cmd
}

func isNotImplicitReadFromStdinSyntax(args []string) bool {
	return strings.Contains(args[0], "=") || len(args) > 1
}

func secretMappingFromSTDIN(ctx context.Context, id string) (*secret, error) {
	data, err := readAllWithContext(ctx, os.Stdin)
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
	parts := strings.Split(arg, "=")
	if len(parts) != 2 {
		return nil, fmt.Errorf("no key=value pair: %s", arg)
	}
	return &secret{id: parts[0], val: parts[1]}, nil
}

func readAllWithContext(ctx context.Context, r io.Reader) ([]byte, error) {
	lines := make(chan []byte)
	errs := make(chan error)

	go func() {
		defer close(lines)
		defer close(errs)

		reader := bufio.NewReader(r)
		line, err := reader.ReadBytes('\n')
		switch {
		case err == io.EOF:
			lines <- line
		case err != nil:
			errs <- err
		default:
			lines <- line
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errs:
		return nil, err
	case line := <-lines:
		return line, nil
	}
}
