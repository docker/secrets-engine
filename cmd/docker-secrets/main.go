package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/alecthomas/kong"
	"github.com/docker/secrets-engine/pkg/handlers"
	"github.com/docker/secrets-engine/pkg/secrets"
)

func main() {
	ctx := kong.Parse(&CLI)

	if err := ctx.Run(); err != nil {
		printAndExit(err, "command failed")
	}
}

var CLI struct {
	Get   getCmd   `cmd:"" help:"Get a secret for the secret store"`
	Set   setCmd   `cmd:"" help:"Set a secret for the secret store"`
	Rm    rmCmd    `cmd:"" help:"Remove a secret from the secret store"`
	Ls    listCmd  `cmd:"" help:"List secrets in the secret store"`
	Serve serveCmd `cmd:"" help:"Serve the secrets API"`
}

type setCmd struct {
	ID    string `arg:""`
	Value []byte `arg:"" type:"filecontent" default:"-"`
}

func (cmd *setCmd) Run() error {
	id, err := secrets.ParseID(cmd.ID)
	if err != nil {
		return fmt.Errorf("parsing sercet id %q: %w", cmd.ID, err)
	}

	store := &localStore{}
	return store.PutSecret(id, cmd.Value)
}

type getCmd struct {
	ID   string `arg:""`
	JSON bool
}

func (cmd *getCmd) Run() error {
	store := &localStore{}
	id, err := secrets.ParseID(cmd.ID)
	if err != nil {
		return fmt.Errorf("parsing sercet id %q: %w", cmd.ID, err)
	}
	envelope, err := store.GetSecret(secrets.Request{ID: id})
	if err != nil {
		return fmt.Errorf("resolving secret: %w", err)
	}

	if cmd.JSON {
		p, err := json.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("marshaling envelope to json: %w", err)
		}
		os.Stdout.Write(p)
	} else {
		os.Stdout.Write(envelope.Value)
	}

	return nil
}

type rmCmd struct {
	ID []string `arg:""`
}

func (cmd *rmCmd) Run() error {
	store := &localStore{}
	for _, idUnsafe := range cmd.ID {
		id, err := secrets.ParseID(idUnsafe)
		if err != nil {
			return fmt.Errorf("parsing sercet id %q: %w", idUnsafe, err)
		}
		if err := store.DeleteSecret(id); err != nil {
			if !errors.Is(err, secrets.ErrNotFound) {
				return fmt.Errorf("removing secret %q: %w", id, err)
			}
		}
	}
	return nil
}

type listCmd struct {
	JSON bool `help:"Output in JSON format"`
}

func (cmd *listCmd) Run() error {
	store := &localStore{}
	envelopes, err := store.ListSecrets()
	if err != nil {
		return fmt.Errorf("listing secrets: %w", err)
	}
	if cmd.JSON {
		p, err := json.Marshal(envelopes)
		if err != nil {
			return fmt.Errorf("marshaling envelope to json: %w", err)
		}
		os.Stdout.Write(p)
	} else {
		for _, envelope := range envelopes {
			fmt.Printf("%s\n", envelope.ID)
		}
	}

	return nil
}

type serveCmd struct {
	SocketAddr string `type:"path" name:"socket" default:"/var/run/docker-secrets-local.sock" help:"Socket path for secrets API"`
}

func (cmd *serveCmd) Run() error {
	if err := os.Remove(cmd.SocketAddr); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing socket %q: %w", cmd.SocketAddr, err)
	}
	listener, err := net.Listen("unix", cmd.SocketAddr)
	if err != nil {
		return fmt.Errorf("listening on %q: %w", cmd.SocketAddr, err)
	}
	defer listener.Close()

	store := &localStore{}
	mux := http.NewServeMux()
	mux.Handle(handlers.Resolver(store))
	return http.Serve(listener, mux)
}

func printAndExit(err error, format string, args ...any) {
	args = append(args, err)
	fmt.Fprintf(os.Stderr, "error: "+format+": %v\n", args...)
	os.Exit(1)
}

type localStore struct{}

func (store *localStore) GetSecret(req secrets.Request) (secrets.Envelope, error) {
	return getSecret(req.ID)
}

func (store *localStore) PutSecret(id secrets.ID, value []byte) error {
	return putSecret(id, value)
}

func (store *localStore) DeleteSecret(id secrets.ID) error {
	return deleteSecret(id)
}

func (store *localStore) ListSecrets() ([]secrets.Envelope, error) {
	return listSecrets()
}
