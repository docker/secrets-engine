package injector

import (
	"context"

	"github.com/docker/docker/api/types/container"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/x/secrets"
)

type Injector struct {
	resolver secrets.Resolver
}

func New(options ...client.Option) (*Injector, error) {
	c, err := client.New(options...)
	if err != nil {
		return nil, err
	}
	return &Injector{
		resolver: c,
	}, nil
}

func (i *Injector) ContainerCreateRequestRewrite(context.Context, *container.CreateRequest) error {
	return nil
}
