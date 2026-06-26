# Secrets Engine SDK

[![unit tests](https://github.com/docker/secrets-engine/actions/workflows/unittests.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/unittests.yml)
[![lint](https://github.com/docker/secrets-engine/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/lint.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-purple)](https://github.com/docker/secrets-engine/blob/main/LICENSE)

Secrets Engine and [docker pass](https://docs.docker.com/reference/cli/docker/pass/)
are bundled with [Docker Desktop](https://docs.docker.com/desktop/).

## Docker CE (experimental / early access)

Runtime secret injection is now available in Docker CE as an **experimental,
early-access** feature. It requires Docker Engine (`dockerd`) **29.2.0 or
higher**.

### Install

Download the latest packages for your Linux distribution from the
[releases](https://github.com/docker/secrets-engine/releases), then install them:
```shell
# Replace with the files you downloaded (matching your distro and arch).
sudo apt install ./DockerSecretsEngine-linux-amd64-ubuntu2404.deb \
                 ./DockerSecretsEnginePlugins-linux-ubuntu2404.deb
systemctl --user daemon-reload
systemctl --user enable --now docker-secrets-engine.service
```

Recommended:
- `dbus` — required for the keyring backends.
- `gnome-keyring` or `kwallet` — secret storage backend.

### Uninstall

```shell
systemctl --user disable --now docker-secrets-engine.service
sudo apt remove docker-secrets-engine-plugins docker-secrets-engine
```

> [!WARNING]
> Docker CE support is experimental and may change between releases. Do not
> rely on it for production workloads yet. Also see
> [known limitations](#known-limitations).

## Runtime secret injection (no plaintext in your CLI or Compose)

Secrets Engine lets you **reference** secrets in `docker run` / `docker compose`
and have Docker **resolve and inject** the real values _at runtime_.

**Key idea:** you pass a _pointer_, not the secret.

- In your config (CLI flags / Compose files), you use a `se://` reference like `se://foo`.
- When the container starts, Docker asks Secrets Engine to resolve that reference
  and injects the secret into the container.
- The secret value is sourced from a provider, such as **`docker pass`**, which
  stores secrets securely in your **local OS keychain** (or from a custom provider plugin).

This means you don’t need:

- host environment variables containing secret values
- plaintext secret files on disk (such as `.env` files)
- secret literals embedded in `compose.yaml`

### Example: store once, use everywhere

Store the secret in your OS keychain:

```bash
docker pass set foo=bar
```

Run a container using a secret reference (the value se://foo is not the secret itself):

```bash
docker run --rm -e foo=se://foo busybox sh -c 'echo "$foo"'
```

Compose example:

```yaml
services:
  app:
    image: your/image
    environment:
      API_TOKEN: se://foo
```

### Realms (namespace + pattern matching)

Secrets Engine supports **realms**: a simple namespacing scheme that helps to
organize secrets by purpose, environment, application, or target system, and then retrieve
them using glob-style patterns.

A realm is a prefix in the secret key. For example:

- `docker/auth/hub/mysecret`
- `docker/auth/ghcr/token`
- `docker/db/prod/password`

Because the realm is part of the key, you can query or operate on groups of
secrets using patterns. For example, to target _all_ Docker auth-related secrets:

- `docker/auth/**`

This makes it easy to:

- keep related secrets grouped together
- separate environments (e.g. `prod/`, `staging/`, `dev/`)
- scope listing/lookup operations to a subset of secrets without knowing every
  key ahead of time

#### Example layout

```text
docker/
  auth/
    hub/
      mysecret
    ghcr/
      token
  db/
    prod/
      password
```

> [!TIP]
> Treat realms like paths - predictable structure makes automation and access control much easier.

> [!NOTE]
> **Missing a plugin?** Help us pick the next provider — vote 👍 for your favorite (or request one) on the [plugin backends epic](https://github.com/docker/secrets-engine/issues/534).

# Developer Guides

## How to query secrets

Use the `client` module in your project:

```shell
go get github.com/docker/secrets-engine/client
```

Use the client to fetch a secret:

```go
c, err := client.New()
if err != nil {
    log.Fatalf("failed to create secrets engine client: %v", err)
}

// Fetch a secret from the engine
// We are using an exact match here, so only one or zero results will return.
secrets, err := c.GetSecrets(context.Background(), client.MustParsePattern("my-secret"))
if errors.Is(err, client.ErrSecretNotFound) {
    log.Fatalf("no secret found")
}
// fallback to generic error
if err != nil {
    log.Fatalf("failed fetching secrets: %v", err)
}
fmt.Println(secrets[0].Value)
```

## How to create a plugin

### 1. Implement the plugin interface

Use the `plugin` module in your project:

```shell
go get github.com/docker/secrets-engine/plugin
```

A plugin needs to implement the `Plugin` interface:

```go
var _ plugin.Plugin = &myPlugin{}

type myPlugin struct {
	m      sync.Mutex
	secrets map[plugin.ID]string
}

func (p *myPlugin) GetSecrets(_ context.Context, pattern plugin.Pattern) ([]plugin.Envelope, error) {
	p.m.Lock()
	defer p.m.Unlock()

	var result []plugin.Envelope
	for id, value := range p.secrets {
		if pattern.Match(id) {
			result = append(result, plugin.Envelope{
				ID:    id,
				Value: []byte(value),
				CreatedAt: time.Now(),
			})
		}
	}
	return result, nil
}

func (p *myPlugin) Run(ctx context.Context) error {
    // add long-running tasks here
    // for example, OAuth tokens can be refreshed here.
	<-ctx.Done()
	return nil
}
```

### 2. Build a plugin binary

Create a Go binary that use your plugin interface implementation and runs it through the plugin SDK:

```go
package main

import (
	"context"
    "fmt"
	"log/slog"

	"github.com/docker/secrets-engine/plugin"
)

type myLogger struct{}

func (m *myLogger) Errorf(format string, v ...any) {
	slog.Error(fmt.Sprintf(format, v...))
}

func (m *myLogger) Printf(format string, v ...any) {
	slog.Info(fmt.Sprintf(format, v...))
}

func (m *myLogger) Warnf(format string, v ...any) {
	slog.Warn(fmt.Sprintf(format, v...))
}

func main() {
    config := plugin.Config{
		Version: plugin.MustNewVersion("v0.0.1"),
		Pattern: plugin.MustParsePattern("myrealm/**"),
        // custom logger
		Logger:  &myLogger{},
	}
    secrets := map[plugin.ID]string{
        plugin.MustParseID("myrealm/foo"): "bar",
    }
	p, err := plugin.New(&myPlugin{secrets: secrets}, config)
	if err != nil {
		panic(err)
	}
    // Run your plugin
	if err := p.Run(context.Background()); err != nil {
		panic(err)
	}
}
```

### 3. Query secrets from your plugin:

To verify your plugin works, run the binary and it should connect to the
Secrets Engine.

As a quick test we can retrieve secrets using `curl`, when running standalone
the default socket is `daemon.sock` and with Docker Desktop it is `engine.sock`.
Below we will query the Secrets Engine in standalone mode.

```bash
curl --unix-socket ~/Library/Caches/docker-secrets-engine/daemon.sock \
    -X POST http://localhost/resolver.v1.ResolverService/GetSecrets \
    -H "Content-Type: application/json" \
    -d '{"pattern": "myrealm/**"}'
```

The value of a secret is always encoded into base64.
When using Go's `json.Unmarshal` it will automatically convert it back into
a slice of bytes `[]byte`.

To manually decode it, you can pipe the value into `base64`, using the
flags appropriate for your platform:

```bash
# macOS / BSD
echo "<base64 string>" | base64 -D

# GNU/Linux (coreutils)
echo "<base64 string>" | base64 --decode
# or
echo "<base64 string>" | base64 -d
```

## Known limitations and issues

These apply to the experimental Docker CE integration described above. We are
actively working to address them.

- **No multi-user support.** A single Docker Engine is shared by every user on
  the host, but Secrets Engine runs as a per-user daemon. When multiple users
  are logged in and using the same engine in parallel, the engine cannot
  reliably route a resolution request to the right user's daemon. As a
  consequence, the user the daemon talks to is fixed at install time: the
  package's post-install script records the installing user's UID (resolved from
  `$SUDO_UID`, i.e. the user who ran `sudo apt install` / `sudo dnf install`)
  into `/etc/docker/nri/conf.d/10-secrets-engine.conf`. If the UID
  cannot be determined at install time, the config is left unset and the integration stays inert until it is
  configured manually.
- **Requires a keyring backend.** The daemon depends on D-Bus together with a
  Secret Service provider (GNOME Keyring or KWallet). On hosts where these are
  missing — typically headless or server installs — the daemon currently crashes
  instead of degrading gracefully. We are working on a fix; in the meantime, the
  workaround is to install and set up D-Bus and either GNOME Keyring or KWallet.

## Legal

_Brought to you courtesy of our legal counsel. For more context,
see the [NOTICE](https://github.com/docker/secrets-engine/blob/main/NOTICE) document in this repo._

Use and transfer of Docker may be subject to certain restrictions by the
United States and other governments.

It is your responsibility to ensure that your use and/or transfer does not
violate applicable laws.

For more information, see https://www.bis.doc.gov

## Licensing

docker/secrets-engine is licensed under the Apache License, Version 2.0. See
[LICENSE](https://github.com/docker/secrets-engine/blob/main/LICENSE) for the full
license text.
