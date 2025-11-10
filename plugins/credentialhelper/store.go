package credentialhelper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/docker/docker-credential-helpers/client"

	"github.com/docker/secrets-engine/engine"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

// KeyRewriter provides a credential-helper credential ID (a server URL).
// The server URL can consist of an http or https prefix and may end with
// a trailing forward-slash
type KeyRewriter func(serverURL string) (secrets.ID, error)

type credentialHelperStore struct {
	client.ProgramFunc
	logging.Logger
	rewriter KeyRewriter
}

func (s *credentialHelperStore) GetSecrets(_ context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	credentials, err := client.List(s.ProgramFunc)
	if err != nil {
		return nil, err
	}

	result := []secrets.Envelope{}

	resolvedAt := time.Now()

	replacer := strings.NewReplacer("https://", "", "http://", "")
	for serverURL := range credentials {
		var p secrets.ID
		var err error

		if s.rewriter != nil {
			p, err = s.rewriter(serverURL)
		} else {
			// some credentials have a trailing '/'
			o := strings.TrimSuffix(replacer.Replace(serverURL), "/")
			p, err = secrets.ParseID(o)
		}

		if err != nil {
			s.Warnf("could not parse key '%s' as secrets.ID: %s", serverURL, err)
			continue
		}
		if pattern.Match(p) {
			cred, err := client.Get(s.ProgramFunc, serverURL)
			// ignore the error if we could not fetch it from credential-helper
			if err != nil {
				s.Warnf("could not get matched secret key '%s' from the credential-helper: %s", serverURL, err)
				continue
			}
			result = append(result, secrets.Envelope{
				ID:         p,
				Value:      []byte(cred.Secret),
				Provider:   "docker-credential-helper",
				Version:    "0.0.1",
				ResolvedAt: resolvedAt,
			})
		}
	}
	if len(result) == 0 {
		return nil, secrets.ErrNotFound
	}
	return result, nil
}

func (s *credentialHelperStore) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

var _ engine.Plugin = &credentialHelperStore{}

// only the CLI owns the config file
// unfortunately it also specifies the credential helper in use
// to support the credential-helper for legacy credentials
// we need to support this env.
// https://github.com/docker/cli/blob/master/cli/config/config.go#L24
const envOverrideConfigDir = "DOCKER_CONFIG"

func getConfigPath() string {
	configDir := os.Getenv(envOverrideConfigDir)
	if configDir != "" {
		return configDir
	}

	// continue with normal config resolution
	// https://github.com/docker/cli/blob/1c572a10de5b9645045e3868b72f0863b920bd13/cli/config/config.go#L61-L69
	home, _ := os.UserHomeDir()
	if home == "" && runtime.GOOS != "windows" {
		if u, err := user.Current(); err == nil {
			home = u.HomeDir
		}
	}

	// there might be a case here where a system does not report a home
	// directory based on the above steps taken from the CLI.
	// We will error when we try to open a non-exiting file.
	return path.Join(home, ".docker", "config.json")
}

type Options func(*credentialHelperStore)

func WithKeyRewriter(rewriter KeyRewriter) Options {
	return func(chs *credentialHelperStore) {
		chs.rewriter = rewriter
	}
}

func WithShellProgramFunc(f client.ProgramFunc) Options {
	return func(chs *credentialHelperStore) {
		chs.ProgramFunc = f
	}
}

func New(logger logging.Logger, opts ...Options) (engine.Plugin, error) {
	c := &credentialHelperStore{
		Logger: logger,
	}
	for _, opt := range opts {
		opt(c)
	}

	if c.ProgramFunc == nil {
		configPath := getConfigPath()
		f, err := os.Open(configPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		// limit the size of the file we are reading.
		// Don't want the plugin to get taken down by a really large file.
		config, err := io.ReadAll(io.LimitReader(f, 1024*1024))
		if err != nil {
			return nil, err
		}

		var v map[string]any
		if err := json.Unmarshal(config, &v); err != nil {
			return nil, err
		}
		suffix, ok := v["credsStore"].(string)
		if !ok || suffix == "" {
			return nil, fmt.Errorf("credential-helper not specified in '%s'", configPath)
		}

		c.ProgramFunc = client.NewShellProgramFunc("docker-credential-" + suffix)
	}

	return c, nil
}
