package main

import (
	"context"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

func main() {
	l := logging.NewDefaultLogger("test-client")
	c, err := client.New()
	if err != nil {
		l.Errorf("could not create a client: %s", err)
		panic(err)
	}

	envelope, err := c.GetSecrets(context.Background(), secrets.MustParsePattern("**"))
	if err != nil {
		l.Errorf("could not get secrets: %s", err)
		panic(err)
	}

	l.Printf("got envelope: %+v", envelope)
}
