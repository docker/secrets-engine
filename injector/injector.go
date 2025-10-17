package injector

import (
	"context"
	"errors"
	"strings"

	"github.com/docker/docker/api/types/container"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

type Option = client.Option

var (
	WithSocketPath = client.WithSocketPath
	WithTimeout    = client.WithTimeout

	ErrSecretNotFound = secrets.ErrNotFound
)

var ErrInvalidEnvName = errors.New("invalid environment variable name")

const (
	prefix               = "se://"
	illegalEnvCharacters = `!@#$%^&*()-+=\{}[]|;:'",<>?/ `
	name                 = "secrets-engine-injector"
)

func int64counter(counter string, opts ...metric.Int64CounterOption) metric.Int64Counter {
	reqs, err := otel.Meter(name).Int64Counter(counter, opts...)
	if err != nil {
		otel.Handle(err)
		reqs, _ = noop.NewMeterProvider().Meter(name).Int64Counter(counter, opts...)
	}
	return reqs
}

func hasIllegalChars(env string) bool {
	for _, c := range illegalEnvCharacters {
		if strings.Contains(env, string(c)) {
			return true
		}
	}
	return false
}

type resolver struct {
	logger       logging.Logger
	resolver     secrets.Resolver
	envsResolved metric.Int64Counter
}

func newResolver(logger logging.Logger, options ...client.Option) (*resolver, error) {
	c, err := client.New(options...)
	if err != nil {
		return nil, err
	}
	return &resolver{
		logger:   logger,
		resolver: c,
		envsResolved: int64counter("secrets.injector.env",
			metric.WithDescription("Total secrets in env injected by the injector client."),
			metric.WithUnit("{injection}")),
	}, nil
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
	getSecrets := func(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
		result, err := r.resolver.GetSecrets(ctx, pattern)
		if err == nil {
			r.envsResolved.Add(ctx, 1)
		}
		return result, err
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

	result, err := getSecrets(ctx, pattern)
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

func New(logger logging.Logger, options ...client.Option) (*ContainerCreateRewriter, error) {
	resolver, err := newResolver(logger, options...)
	if err != nil {
		return nil, err
	}
	return &ContainerCreateRewriter{r: resolver}, nil
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
