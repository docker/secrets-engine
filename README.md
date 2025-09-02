# Docker Secrets Engine

[![build](https://github.com/docker/secrets-engine/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/build.yml)
[![unit tests](https://github.com/docker/secrets-engine/actions/workflows/unittests.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/unittests.yml)
[![lint](https://github.com/docker/secrets-engine/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/lint.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](https://github.com/docker/secrets-engine/blob/main/LICENSE)

## Getting Started

Run a local engine:

```console
$ make engine
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o ./dist/secrets-engine ./engine/daemon
$ ./dist/secrets-engine
2025/08/12 10:20:45 engine: secrets engine starting up... (~/.cache/secrets-engine/engine.sock)
2025/08/12 10:20:45 engine: discovered builtin plugin: mysecret
2025/08/12 10:20:45 engine: registering plugin 'mysecret'...
2025/08/12 10:20:45 engine: plugin priority order
2025/08/12 10:20:45 engine:   #1: mysecret
2025/08/12 10:20:45 engine: secrets engine ready
```

Create secrets in your keychain:

```console
$ make mysecret
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o ./dist/docker-mysecret ./mysecret
$ ./dist/docker-mysecret set foo=bar
$ ./dist/docker-mysecret set baz=something
$ ./dist/docker-mysecret ls
baz
foo
```

Query secrets from the engine:

```console
$ curl --unix-socket ~/.cache/secrets-engine/engine.sock \
    -X POST http://localhost/resolver.v1.ResolverService/GetSecrets \
    -H "Content-Type: application/json" -d '{"pattern": "foo"}'
{"id":"foo","value":"bar","provider":"mysecret","version":"","error":"","createdAt":"0001-01-01T00:00:00Z","resolvedAt":"2025-08-12T08:25:06.166714Z","expiresAt":"0001-01-01T00:00:00Z"}
```

> [!NOTE]
> On linux the socket might be on /run/user/1000/secrets-engine/engine.sock

## Integration

There are three ways to integrate with the secrets engine:

- Client integrator: Use the client to query secrets and to build business logic on top that makes use of the engine.
- Plugin author: Create plugins for an engine.
- Engine integrator: Build/run an engine yourself.

### Using the client

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

### Writing your own Plugin

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

func (p *myPlugin) GetSecret(_ context.Context, request secrets.Request) (secrets.Envelope, error) {
	p.m.Lock()
	defer p.m.Unlock()
	for id, value := range p.secrets {
		if request.ID == id {
			return secrets.Envelope{
				ID:    id,
				Value: []byte(value),
				CreatedAt: time.Now(),
			}, nil
		}
	}
	return secrets.EnvelopeErr(request, secrets.ErrNotFound), secrets.ErrNotFound
}

func (p *myPlugin) Config() plugin.Config {
	return plugin.Config{
		Version: "v0.0.1",
		Pattern: "*",
	}
}
```

Create your plugin binary:

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

### Running the Engine

TODO
