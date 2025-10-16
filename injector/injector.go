package injector

import (
	"context"
	"errors"
	"strings"

	"github.com/docker/docker/api/types/container"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

const prefix = "se://"

type resolver struct {
	logger   logging.Logger
	resolver secrets.Resolver
}

func newResolver(logger logging.Logger, options ...client.Option) (*resolver, error) {
	c, err := client.New(options...)
	if err != nil {
		return nil, err
	}
	return &resolver{
		logger:   logger,
		resolver: c,
	}, nil
}

func (r *resolver) resolveENV(ctx context.Context, key, value string) (string, error) {
	if key == "" {
		return "", errors.New("key is required")
	}
	if value == "" {
		id, err := secrets.ParseID(key)
		if err != nil {
			r.logger.Printf("%s has no value but is not a valid secret ID (%s) -> cannot resolve", key, err)
			return "", nil
		}
		result, err := r.resolver.GetSecrets(ctx, secrets.MustParsePattern(id.String()))
		if err != nil {
			if !errors.Is(err, secrets.ErrNotFound) {
				r.logger.Errorf("resolving ENV %s to secret: %s", key, err)
			}
			return "", nil
		}
		if len(result) == 0 {
			return "", nil
		}
		return string(result[0].Value), nil
	}
	if !strings.HasPrefix(value, prefix) {
		return value, nil
	}
	unprefixedValue := strings.TrimPrefix(value, prefix)
	pattern, err := secrets.ParsePattern(unprefixedValue)
	if err != nil {
		return "", err
	}
	result, err := r.resolver.GetSecrets(ctx, pattern)
	if err != nil {
		return "", err
	}
	if len(result) == 0 {
		return "", secrets.ErrNotFound
	}
	return string(result[0].Value), nil
}

type ContainCreateRewriter struct {
	r *resolver
}

func New(logger logging.Logger, options ...client.Option) (*ContainCreateRewriter, error) {
	resolver, err := newResolver(logger, options...)
	if err != nil {
		return nil, err
	}
	return &ContainCreateRewriter{r: resolver}, nil
}

func (r *ContainCreateRewriter) ContainerCreateRequestRewrite(context.Context, *container.CreateRequest) error {
	return nil
}
