package injector

import (
	"context"
	"errors"
	"strings"

	"github.com/moby/moby/api/types/container"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/telemetry"
)

type (
	Option = client.Option

	Tracker = telemetry.Tracker
)

var (
	WithSocketPath  = client.WithSocketPath
	WithDialContext = client.WithDialContext
	WithTimeout     = client.WithTimeout

	ErrSecretNotFound = secrets.ErrNotFound
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
	tracker  telemetry.Tracker
}

func newResolver(logger logging.Logger, tracker telemetry.Tracker, options ...client.Option) (*resolver, error) {
	c, err := client.New(options...)
	if err != nil {
		return nil, err
	}
	return &resolver{
		logger:   logger,
		resolver: c,
		tracker:  tracker,
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
	getSecrets := func(ctx context.Context, pattern secrets.Pattern, src string) ([]secrets.Envelope, error) {
		result, err := r.resolver.GetSecrets(ctx, pattern)
		if err == nil && len(result) > 0 {
			r.tracker.TrackEvent(EventSecretsEngineInjectorEnvResolved{Source: src})
		}
		return result, err
	}

	if hasIllegalChars(key) {
		return "", withNoErrLegacyFallback(ErrInvalidEnvName)
	}

	src := sourceValue
	v := value
	if v == "" {
		v = key
		src = sourceKey
	}
	pattern, err := secrets.ParsePattern(strings.TrimPrefix(v, prefix))
	if err != nil {
		return "", withNoErrLegacyFallback(err)
	}

	result, err := getSecrets(ctx, pattern, src)
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

const (
	sourceKey   = "key"
	sourceValue = "value"
)

type EventSecretsEngineInjectorEnvResolved struct {
	Source string `json:"source"`
}

type ContainerCreateRewriter struct {
	r              *resolver
	legacyFallback bool
}

// New creates a new injector resolver.
// If [logger] is nil, a noop logger will be used. If [tracker] is nil, a noop tracker will be used.
// With [legacyFallback] enabled, for ENVs with empty value, the key will be tried to resolve as secret.
func New(logger logging.Logger, tracker telemetry.Tracker, legacyFallback bool, options ...client.Option) (*ContainerCreateRewriter, error) {
	if tracker == nil {
		tracker = telemetry.NoopTracker()
	} else {
		tracker = telemetry.AsyncWrapper(tracker)
	}
	resolver, err := newResolver(logger, tracker, options...)
	if err != nil {
		return nil, err
	}
	return &ContainerCreateRewriter{r: resolver, legacyFallback: legacyFallback}, nil
}

func (r *ContainerCreateRewriter) ContainerCreateRequestRewrite(ctx context.Context, req *container.CreateRequest) error {
	if req.Config == nil {
		return nil
	}
	var resolvedEnvList []string
	for _, env := range req.Env {
		key, val, _ := strings.Cut(env, "=")
		if val == "" && !r.legacyFallback {
			resolvedEnvList = append(resolvedEnvList, env)
			continue
		}
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
