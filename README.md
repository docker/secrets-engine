Docker Secrets Engine
=====================

[![Main pipeline](https://github.com/docker/secrets-engine/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/docker/secrets-engine/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](https://github.com/docker/secrets-engine/blob/main/LICENSE)


## Usage

### Client

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
