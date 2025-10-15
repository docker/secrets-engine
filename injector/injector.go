package injector

import (
	"context"

	"github.com/docker/docker/api/types/container"
)

func ContainerCreateRequestRewrite(context.Context, *container.CreateRequest) error {
	return nil
}
