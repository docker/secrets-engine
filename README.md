# Secrets Engine SDK

[![unit tests](https://github.com/docker/secrets-engine/actions/workflows/unittests.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/unittests.yml)
[![lint](https://github.com/docker/secrets-engine/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/lint.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-purple)](https://github.com/docker/secrets-engine/blob/main/LICENSE)

Secrets Engine and [docker pass](https://docs.docker.com/reference/cli/docker/pass/)
ship with [Docker Desktop](https://docs.docker.com/desktop/).

## Docker CE (experimental)

Docker CE includes runtime secret injection as an **experimental** feature. It
requires Docker Engine (`dockerd`) **29.2.0 or higher**. Install the packages
from Docker's official repository at `download.docker.com`, or download them
from the [releases page](https://github.com/docker/secrets-engine/releases).

### Set up Docker's package repository

Skip this step if you already installed Docker Engine from
`download.docker.com`. Otherwise, add the repository with the official
convenience script:

```shell
curl -fsSL https://get.docker.com | sh -s -- --setup-repo
```

Or follow the
[Docker Engine installation instructions](https://docs.docker.com/engine/install/).

### Install

**apt (Debian/Ubuntu):**

```shell
sudo apt-get update
sudo apt-get install docker-secrets-engine docker-secrets-engine-plugins
```

**dnf (Fedora):**

```shell
sudo dnf install docker-secrets-engine docker-secrets-engine-plugins
```

Then enable the service for your user:

```shell
systemctl --user daemon-reload
systemctl --user enable --now docker-secrets-engine.service
```

Recommended:
- `dbus` — required for the keyring backends.
- `gnome-keyring` or `kwallet` — secret storage backend.

### Uninstall

```shell
systemctl --user disable --now docker-secrets-engine.service

# apt (Debian/Ubuntu)
sudo apt-get remove docker-secrets-engine-plugins docker-secrets-engine

# dnf (Fedora)
sudo dnf remove docker-secrets-engine-plugins docker-secrets-engine
```

> [!WARNING]
> Docker CE support is experimental and may change between releases. Do not
> rely on it for production workloads yet. See
> [known limitations](#known-limitations).

## Runtime secret injection (no plaintext in your CLI or Compose)

Secrets Engine lets you **reference** secrets in `docker run` / `docker compose`
and have Docker **resolve and inject** the real values _at runtime_.

**Key idea:** you pass a _pointer_, not the secret.

- In CLI flags and Compose files, you write a `se://` reference such as `se://foo`.
- When the container starts, Docker asks Secrets Engine to resolve that reference
  and injects the secret into the container.
- A provider supplies the value: **`docker pass`**, which stores secrets in
  your **local OS keychain**, or a custom provider plugin.

You no longer need:

- host environment variables containing secret values
- plaintext secret files on disk (such as `.env` files)
- secret literals in `compose.yaml`

### Example: store once, use everywhere

Store the secret in your OS keychain:

```bash
# recommended: stdin keeps the secret out of the command line (visible in htop) and shell history
docker pass set foo

# or pass the value inline
docker pass set foo=secret
```

Run a container with a secret reference (the value se://foo is not the secret itself):

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
secrets with patterns. To target _all_ Docker auth secrets:

- `docker/auth/**`

This lets you:

- group related secrets
- separate environments (e.g. `prod/`, `staging/`, `dev/`)
- scope listing and lookup to a subset of secrets without knowing every key
  ahead of time

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
> Treat realms like paths: a predictable structure eases automation and access control.

> [!NOTE]
> **Missing a plugin?** Help us pick the next provider — vote 👍 for your favorite (or request one) on the [plugin backends epic](https://github.com/docker/secrets-engine/issues/534).

# Developer Guides

## How to query secrets

Add the `client` module to your project:

```shell
go get github.com/docker/secrets-engine/client
```

Fetch a secret:

```go
c, err := client.New()
if err != nil {
    log.Fatalf("failed to create secrets engine client: %v", err)
}

// Fetch a secret from the engine.
// An exact match returns zero or one result.
secrets, err := c.GetSecrets(context.Background(), client.MustParsePattern("my-secret"))
if errors.Is(err, client.ErrSecretNotFound) {
    log.Fatalf("no secret found")
}
// handle any other error
if err != nil {
    log.Fatalf("failed fetching secrets: %v", err)
}
fmt.Println(secrets[0].Value)
```

## How to fetch a Docker Hub access token

`HubAuth()` returns a Docker Hub authentication accessor. It locates the right
credential and decodes the JSON payload into a typed `UserSession`, so you
don't need to know the realm layout or the payload format:

```go
import (
    "github.com/docker/secrets-engine/client"
    "github.com/docker/secrets-engine/client/dockerhub"
)

c, err := client.New()
if err != nil {
    log.Fatalf("failed to create secrets engine client: %v", err)
}
hub := c.HubAuth()

// Fetch the session of the default signed-in account ...
session, err := hub.GetDefaultSession(context.Background())
if errors.Is(err, dockerhub.ErrNoSession) {
    // Also matches dockerhub.ErrNoDefaultProfile, which wraps ErrNoSession.
    log.Fatalf("not signed in to Docker Hub")
}
if err != nil {
    log.Fatalf("failed fetching access token: %v", err)
}

// ... or fetch the session of a specific account.
session, err = hub.GetSession(context.Background(), "myuser")
if err != nil {
    log.Fatalf("failed fetching access token: %v", err)
}

fmt.Println(session.AccessToken)       // the raw JWT access token
fmt.Println(session.Claims.Username)   // decoded token claims
fmt.Println(session.Claims.ExpiresAt)

// List the profiles of all signed-in accounts.
profiles, err := hub.ListProfiles(context.Background())
if err != nil {
    log.Fatalf("failed listing profiles: %v", err)
}
for _, profile := range profiles {
    fmt.Println(profile.Username, profile.UserID)
}
```

## How to create a plugin

### 1. Implement the plugin interface

Add the `plugin` module to your project:

```shell
go get github.com/docker/secrets-engine/plugin
```

A plugin implements the `Plugin` interface:

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
    // Long-running work goes here — refreshing OAuth tokens, for example.
	<-ctx.Done()
	return nil
}
```

### 2. Build a plugin binary

Create a Go binary that uses your plugin interface implementation and runs it through the plugin SDK:

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
		SecretsProviderConfig: &plugin.SecretsProviderConfig{
			Pattern: plugin.MustParsePattern("myrealm/**"),
		},
        // custom logger
		Logger:  &myLogger{},
	}
    secrets := map[plugin.ID]string{
        plugin.MustParseID("myrealm/foo"): "bar",
    }
	p, err := plugin.NewSecretsProvider(&myPlugin{secrets: secrets}, config)
	if err != nil {
		panic(err)
	}
    // Run your plugin
	if err := p.Run(context.Background()); err != nil {
		panic(err)
	}
}
```

### 3. Query secrets from your plugin

To verify your plugin works, run the binary; it connects to the Secrets Engine.

Test it by retrieving secrets with `curl`. Standalone, the engine listens on
`daemon.sock`; under Docker Desktop, on `engine.sock`. This example queries
standalone mode:

```bash
curl --unix-socket ~/Library/Caches/docker-secrets-engine/daemon.sock \
    -X POST http://localhost/resolver.v1.ResolverService/GetSecrets \
    -H "Content-Type: application/json" \
    -d '{"pattern": "myrealm/**"}'
```

The engine always returns secret values base64-encoded. Go's `json.Unmarshal`
decodes them to `[]byte`.

To decode by hand, pipe the value through `base64` with the flag for your
platform:

```bash
# macOS / BSD
echo "<base64 string>" | base64 -D

# GNU/Linux (coreutils)
echo "<base64 string>" | base64 --decode
# or
echo "<base64 string>" | base64 -d
```

## Known limitations

These apply to the experimental Docker CE integration described above. We are
working to address them.

- **No multi-user support.** One Docker Engine serves every user on the host,
  but Secrets Engine runs as a per-user daemon. With several users on the same
  engine in parallel, it cannot reliably route a resolution request to the
  right user's daemon. The engine therefore targets one fixed user's daemon,
  chosen at install time: the package's post-install script records the
  installing user's UID (from `$SUDO_UID`, the user who ran `sudo apt install`
  / `sudo dnf install`) in `/etc/docker/nri/conf.d/10-secrets-engine.conf`. If
  the UID cannot be determined at install time, the config stays unset and the
  integration stays inert until configured manually.
- **Requires a keyring backend.** The daemon needs D-Bus and a Secret Service
  provider (GNOME Keyring or KWallet). On hosts that lack them — typically
  headless or server installs — the daemon crashes instead of degrading
  gracefully. Until we ship a fix, install and set up D-Bus and either GNOME
  Keyring or KWallet.

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
