// Copyright 2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime/debug"

	"github.com/docker/secrets-engine/client/config"
	clientversion "github.com/docker/secrets-engine/client/version"
	"github.com/docker/secrets-engine/plugin"
)

const pluginName = "stdinreader"

// Run reads dotenv-formatted secrets from stdin, connects to the secrets
// engine daemon, and serves the secrets as the stdinreader plugin.
// buildVersion is the plugin's build version (typically injected via
// -ldflags). When it is empty or "dev", the module version from the build
// info applies.
func Run(ctx context.Context, buildVersion string) error {
	logger := newStderrLogger(pluginName)

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading secrets from stdin: %w", err)
	}

	secretsByID, err := parseSecrets(raw)
	zero(raw)
	if err != nil {
		return err
	}

	socketPath := config.StandaloneSocketPath()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("connecting to secrets engine at %q: %w", socketPath, err)
	}
	defer conn.Close()

	version, err := pluginVersion(buildVersion)
	if err != nil {
		return err
	}

	stub, err := plugin.NewSecretsProvider(
		&resolver{secrets: secretsByID, logger: logger},
		plugin.Config{
			Version: version,
			Logger:  logger,
			SecretsProviderConfig: &plugin.SecretsProviderConfig{
				Pattern: plugin.MustParsePattern("**"),
			},
		},
		plugin.WithPluginName(pluginName),
		plugin.WithConnection(conn),
	)
	if err != nil {
		return fmt.Errorf("creating plugin: %w", err)
	}

	return stub.Run(ctx)
}

func pluginVersion(override string) (plugin.Version, error) {
	if override != "" && override != "dev" {
		return clientversion.NewVersion(override)
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v, err := clientversion.NewVersion(info.Main.Version); err == nil {
			return v, nil
		}
	}
	return clientversion.NewVersion("v0.0.0-not-set")
}

func parseSecrets(raw []byte) (map[plugin.ID][]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("no secrets provided on stdin")
	}

	flat, err := parseDotenv(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing dotenv secrets: %w", err)
	}
	if len(flat) == 0 {
		return nil, errors.New("no secrets provided on stdin")
	}

	out := make(map[plugin.ID][]byte, len(flat))
	for k, v := range flat {
		id, err := plugin.ParseID(k)
		if err != nil {
			// Abandoning the parsed secrets early: wipe every value buffer
			// (those already in out share backing with flat) so no secret
			// bytes linger on the heap until GC.
			for _, sv := range flat {
				zero(sv)
			}
			return nil, fmt.Errorf("invalid secret key %q: %w", k, err)
		}
		out[id] = v
	}
	return out, nil
}

// zero overwrites b with zero bytes.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// parseDotenv parses dotenv-formatted bytes into key/value pairs without
// performing any variable substitution. Secret values are stored verbatim:
// a value like `token$SUFFIX` is preserved literally rather than expanded,
// which would corrupt the credential.
//
// It operates directly on the input bytes (no intermediate string copy of
// the full payload) so that zeroing the caller's buffer also clears the
// parser's working data; only the returned per-value buffers are fresh
// copies that outlive raw.
//
// Supported syntax: blank lines and `#` comment lines are skipped; each
// remaining line is `KEY=VALUE` (an optional leading `export ` is stripped).
// Values may be wrapped in matching single or double quotes, which are
// removed; unquoted values are taken literally after trimming surrounding
// whitespace. No escape sequences are interpreted.
func parseDotenv(raw []byte) (map[string][]byte, error) {
	out := make(map[string][]byte)
	for i, line := range bytes.Split(raw, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		trimmed = bytes.TrimPrefix(trimmed, []byte("export "))

		key, value, ok := bytes.Cut(trimmed, []byte("="))
		if !ok {
			return nil, fmt.Errorf("line %d: missing '=' separator", i+1)
		}
		key = bytes.TrimSpace(key)
		if len(key) == 0 {
			return nil, fmt.Errorf("line %d: empty key", i+1)
		}

		value = bytes.TrimSpace(value)
		if len(value) >= 2 {
			if q := value[0]; (q == '"' || q == '\'') && value[len(value)-1] == q {
				value = value[1 : len(value)-1]
			}
		}
		// Copy so the value outlives (and is independent of) raw, which the
		// caller zeroes after parsing.
		buf := make([]byte, len(value))
		copy(buf, value)
		// A duplicate key rebinds the slot; wipe the displaced buffer so the
		// superseded secret does not linger on the heap until GC.
		if prev, ok := out[string(key)]; ok {
			zero(prev)
		}
		out[string(key)] = buf
	}
	return out, nil
}

type resolver struct {
	secrets map[plugin.ID][]byte
	logger  plugin.Logger
}

var _ plugin.SecretsProvider = (*resolver)(nil)

func (r *resolver) GetSecrets(_ context.Context, pattern plugin.Pattern) ([]plugin.Envelope, error) {
	var result []plugin.Envelope
	for id, value := range r.secrets {
		if !pattern.Match(id) {
			continue
		}
		result = append(result, plugin.Envelope{ID: id, Value: value})
	}
	if len(result) == 0 {
		return nil, plugin.ErrNotFound
	}
	return result, nil
}

type stderrLogger struct {
	logger *log.Logger
}

var _ plugin.Logger = (*stderrLogger)(nil)

func newStderrLogger(prefix string) *stderrLogger {
	return &stderrLogger{logger: log.New(os.Stderr, prefix+": ", log.LstdFlags|log.Lmsgprefix)}
}

func (l *stderrLogger) Printf(format string, v ...any) {
	l.logger.Printf(format, v...)
}

func (l *stderrLogger) Warnf(format string, v ...any) {
	l.logger.Printf("[WARN] "+format, v...)
}

func (l *stderrLogger) Errorf(format string, v ...any) {
	l.logger.Printf("[ERR] "+format, v...)
}
