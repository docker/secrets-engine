# Secrets Engine SDK

[![unit tests](https://github.com/docker/secrets-engine/actions/workflows/unittests.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/unittests.yml)
[![lint](https://github.com/docker/secrets-engine/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/lint.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-purple)](https://github.com/docker/secrets-engine/blob/main/LICENSE)

Secrets Engine and [docker pass](https://docs.docker.com/reference/cli/docker/pass/)
are bundled with [Docker Desktop](https://docs.docker.com/desktop/).
A standalone version can also be installed from the [releases](https://github.com/docker/secrets-engine/releases).

> [!NOTE]
> Secret injection in Docker CE is on our roadmap.

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

To manually decode it, you can pipe the value into `base64 --decode -i`.

```bash
echo "<base64 string>" | base64 --decode -i
```

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
