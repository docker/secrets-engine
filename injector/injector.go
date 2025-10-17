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

var ErrInvalidEnvName = errors.New("invalid environment variable name")

const (
	prefix               = "se://"
	illegalEnvCharacters = `!@#$%^&*()-+=\{}[]|;:'",<>?/ `
)

func hasIllegalChars(env string) bool {
	for _, c := range illegalEnvCharacters {
		if strings.Contains(env, string(c)) {
			return true
		}
	}
	return false
}

type resolver struct {
	logger   logging.Logger
	resolver secrets.Resolver
}

func newResolver(logger logging.Logger, options ...client.Option) *resolver {
	return &resolver{
		logger:   logger,
		resolver: client.New(options...),
	}
}

func (r *resolver) resolveENV(ctx context.Context, key, value string) (string, error) {
	if value != "" && !strings.HasPrefix(value, prefix) {
		return value, nil
	}

	withNoErrLegacyFallback := func(err error) error {
		if value == "" {
			// If the value was empty, but we tried to resolve the key to a secret and failed
			// that should never return an error -> we remain backwards compatible
			return nil
		}
		return err
	}

	if hasIllegalChars(key) {
		return "", withNoErrLegacyFallback(ErrInvalidEnvName)
	}

	v := value
	if v == "" {
		v = key
	}
	pattern, err := secrets.ParsePattern(strings.TrimPrefix(v, prefix))
	if err != nil {
		return "", withNoErrLegacyFallback(err)
	}

	result, err := r.resolver.GetSecrets(ctx, pattern)
	if err != nil {
		if value == "" && !errors.Is(err, secrets.ErrNotFound) {
			r.logger.Errorf("resolving ENV %s to secret: %s", key, err)
		}
		return "", withNoErrLegacyFallback(err)
	}

	if len(result) == 0 {
		return "", withNoErrLegacyFallback(secrets.ErrNotFound)
	}

	return string(result[0].Value), nil
}

type ContainerCreateRewriter struct {
	r *resolver
}

func New(logger logging.Logger, options ...client.Option) *ContainerCreateRewriter {
	return &ContainerCreateRewriter{r: newResolver(logger, options...)}
}

func (r *ContainerCreateRewriter) ContainerCreateRequestRewrite(ctx context.Context, req *container.CreateRequest) error {
	if req.Config == nil {
		return nil
	}
	var resolvedEnvList []string
	for _, env := range req.Env {
		key, val, _ := strings.Cut(env, "=")
		resolved, err := r.r.resolveENV(ctx, key, val)
		if err != nil {
			return err
		}
		if resolved == "" {
			// If no error and nothing got resolved (it means val is empty)
			// keep everything as is (and do not add a '=' character!)
			resolvedEnvList = append(resolvedEnvList, env)
		} else {
			resolvedEnvList = append(resolvedEnvList, key+"="+resolved)
		}
	}
	req.Env = resolvedEnvList
	return nil
}
