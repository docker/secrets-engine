package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/pkg/handlers"
	"github.com/docker/secrets-engine/pkg/providers/local"
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
	Run   runCmd   `cmd:"" help:"Run a container with secrets"`
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

	store := local.New()
	return store.PutSecret(id, cmd.Value)
}

type getCmd struct {
	ID   string `arg:""`
	JSON bool
}

func (cmd *getCmd) Run() error {
	store := local.New()
	id, err := secrets.ParseID(cmd.ID)
	if err != nil {
		return fmt.Errorf("parsing sercet id %q: %w", cmd.ID, err)
	}
	envelope, err := store.GetSecret(context.Background(), secrets.Request{ID: id})
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
	store := local.New()
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
	store := local.New()
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

	store := local.New()
	mux := http.NewServeMux()
	mux.Handle(handlers.Resolver(store))
	return http.Serve(listener, mux)
}

// runCmd is used to demonstrate the entire end to end concept with a
// running server and injection of env, file and api-based secrets.
//
// We project secrets in two ways by default:
// 1. Each secret is written by id into /run/secrets
// 2. We make the API available over unix socket at /run/secrets.sock
type runCmd struct {
	Secrets      []string `name:"secret" help:"Specify one or more secrets for the container"`
	SecretsEnv   []string `name:"secret-env" help:"Make secrets available as env vars in the format ENV=<secret-id>"`
	SecretsAllow []string `name:"secret-allow" help:"Make the secret available to the container only through the API"`
	Args         []string `arg:"" passthrough:"" help:"Arguments for docker run commaned (-it and --rm implied)"`
}

func (cmd *runCmd) Run() error {
	var (
		ctx, cancel = context.WithCancel(context.Background())
		provider    = local.New()
		dockerCmd   = exec.CommandContext(ctx, "docker")

		// For the purposes of the demo mode, we are just going to make a
		// big ol' temp directory and bind mount it.

	)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "docker-secrets-*")
	if err != nil {
		return fmt.Errorf("creating tmpdir for secrets: %w", err)
	}

	// Let's bind the socket to the tmpdir
	socketAddr := filepath.Join(tmpDir, "api.sock")
	listener, err := net.Listen("unix", socketAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %v: %w", socketAddr, err)
	}
	defer listener.Close()

	restricted := secrets.NewRestricted(provider)
	go func() {
		defer cancel() // cancel the context if the server goes down

		mux := http.NewServeMux()
		mux.Handle(handlers.Resolver(restricted))

		// start up the secrets API. In the real version,
		// we route this through the secrets router to a
		// provider but we'll just directly bind the local
		// secrets store in this case.
		if err := http.Serve(listener, mux); err != nil {
			slog.Error("serving local provider failed", "err", err)
			return
		}
	}()

	dockerCmd.Args = []string{"docker", "run", "-it", "--rm"} // imply rm and it to get server lifecyle correct, not required when integrating with moby

	const secretsAPISock = "/run/secrets.sock" // bound outside the secrets tree.
	secretsDir := filepath.Join(tmpDir, "secrets")
	// Sets up the bind mounts. When we integrate with moby engine,
	// simply create a tmpfs tied to the container lifecycle and
	// write the secrets directly in.
	dockerCmd.Args = append(dockerCmd.Args, "-v", socketAddr+":"+secretsAPISock) // socket bound separately
	dockerCmd.Args = append(dockerCmd.Args, "-v", secretsDir+":/run/secrets")

	// provide an env var for the secret unix socket location
	dockerCmd.Args = append(dockerCmd.Args, "--env", "SECRETS_SOCK="+secretsAPISock)

	var allowed []secrets.ID
	for _, secret := range cmd.Secrets {
		id, err := secrets.ParseID(secret)
		if err != nil {
			return fmt.Errorf("invalid secret identifier: %w", err)
		}

		envelope, err := provider.GetSecret(ctx, secrets.Request{ID: id})
		if err != nil {
			return fmt.Errorf("resolving secret: %w", err)
		}

		secretPath := filepath.Join(secretsDir, id.String())
		// make any sub-directories for heirarchical secrets
		if err := os.MkdirAll(filepath.Dir(secretPath), 0o700); err != nil {
			return fmt.Errorf("creating secret path for %q failed: %w", id, err)
		}
		if err := os.WriteFile(secretPath, envelope.Value, 0o600); err != nil {
			return fmt.Errorf("writing secret value for %q failed: %w", id, err)
		}

		allowed = append(allowed, id)
	}

	for _, secret := range cmd.SecretsEnv {
		parts := strings.Split(secret, "=")
		if len(parts) != 2 {
			return fmt.Errorf("invalid secret-env specification %q", secret)
		}
		env := parts[0]
		secret = parts[1]

		id, err := secrets.ParseID(secret)
		if err != nil {
			return fmt.Errorf("invalid secret identifier: %w", err)
		}

		envelope, err := provider.GetSecret(ctx, secrets.Request{ID: id})
		if err != nil {
			return fmt.Errorf("resolving secret: %w", err)
		}

		// Fairly insecure since we leak the secret to the command line but ok for demo purposes.
		dockerCmd.Args = append(dockerCmd.Args, "--env", fmt.Sprintf("%s=%s", env, string(envelope.Value)))

		allowed = append(allowed, id)
	}

	for _, secret := range cmd.SecretsAllow {
		id, err := secrets.ParseID(secret)
		if err != nil {
			return fmt.Errorf("invalid secret identifier: %w", err)
		}

		// make sure the secret is available
		if _, err = provider.GetSecret(ctx, secrets.Request{ID: id}); err != nil {
			return fmt.Errorf("resolving secret: %w", err)
		}

		allowed = append(allowed, id)
	}

	restricted.Allow(allowed...)

	// add the user's arguments to the call
	dockerCmd.Args = append(dockerCmd.Args, cmd.Args...)

	dockerCmd.Stdin = os.Stdin
	dockerCmd.Stdout = os.Stdout
	dockerCmd.Stderr = os.Stderr

	slog.Info("running docker command", "cmd", dockerCmd)
	// pass error to kong, it does the right thing with the ExitCode
	return dockerCmd.Run()
}

func printAndExit(err error, format string, args ...any) {
	args = append(args, err)
	fmt.Fprintf(os.Stderr, "error: "+format+": %v\n", args...)
	os.Exit(1)
}
