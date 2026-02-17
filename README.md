# Secrets Engine SDK

[![build](https://github.com/docker/secrets-engine/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/build.yml)
[![unit tests](https://github.com/docker/secrets-engine/actions/workflows/unittests.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/unittests.yml)
[![lint](https://github.com/docker/secrets-engine/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/lint.yml)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue)](https://github.com/docker/secrets-engine/blob/main/LICENSE)

## Quickstart

Secrets Engine and [docker pass](https://docs.docker.com/reference/cli/docker/pass/) are bundled with [Docker Desktop](https://docs.docker.com/desktop/).

Let's store a secret using `docker pass` in the OS Keychain and then inject it
into a running container using Secrets Engine.

```console
# Store `Foo` in the OS Keychain
$ docker pass set Foo=bar
# Tell docker to use the Secrets Engine using the `se://` URI on an environment variable
$ docker run --rm -e Foo=se://Foo busybox /bin/sh -c "echo \${Foo}"
$ bar
```

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
resp, err := c.GetSecret(t.Context(), secrets.Request{ID: "my-secret"})
if err != nil {
    log.Fatalf("failed fetching secret: %v", err)
}
fmt.Println(resp.Value)
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
	secrets map[secrets.ID]string
}

func (p *myPlugin) GetSecret(_ context.Context, request secrets.Request) ([]secrets.Envelope, error) {
	p.m.Lock()
	defer p.m.Unlock()

	var result []secrets.Envelope
	for id, value := range p.secrets {
		if request.Pattern.Match(id) {
			result = append(result, secrets.Envelope{
				ID:    id,
				Value: []byte(value),
				CreatedAt: time.Now(),
			})
		}
	}
	return result, nil
}

func (p *myPlugin) Config() plugin.Config {
	return plugin.Config{
		Version: "v0.0.1",
		Pattern: "*",
	}
}
```

### 2. Build a plugin binary

Create a Go binary that use your plugin interface implementation and runs it through the plugin SDK:

```go
package main

import (
	"context"

	"github.com/docker/secrets-engine/plugin"
)

func main() {
    p, err := plugin.New(&myPlugin{secrets: map[secrets.ID]string{"foo": "bar"}})
    if err != nil {
        panic(err)
    }
	// Run your plugin
    if err := p.Run(context.Background()); err != nil {
        panic(err)
    }
}
```

### 3. Test and verify the plugin:

The secrets engine is integrated with Docker Desktop.
To verify your plugin works, run the binary.
Using the SDK it will automatically connect to the secrets engine in Docker Desktop.
Then, you can query secrets, e.g. using curl:

```console
$ curl --unix-socket ~/Library/Caches/docker-secrets-engine/engine.sock \
    -X POST http://localhost/resolver.v1.ResolverService/GetSecrets \
    -H "Content-Type: application/json" -d '{"pattern": "foo"}'
{"id":"foo","value":"bar","provider":"docker-pass","version":"","error":"","createdAt":"0001-01-01T00:00:00Z","resolvedAt":"2025-08-12T08:25:06.166714Z","expiresAt":"0001-01-01T00:00:00Z"}
```

