package plugin

import (
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

func NewValidatedConfig(in Unvalidated) (Metadata, error) {
	name, err := api.NewName(in.Name)
	if err != nil {
		return nil, err
	}
	version, err := api.NewVersion(in.Version)
	if err != nil {
		return nil, err
	}
	pattern, err := secrets.ParsePattern(in.Pattern)
	if err != nil {
		return nil, err
	}
	return &configValidated{name: name, version: version, pattern: pattern}, nil
}

type configValidated struct {
	name    api.Name
	version api.Version
	pattern secrets.Pattern
}

func (c configValidated) Name() api.Name {
	return c.name
}

func (c configValidated) Version() api.Version {
	return c.version
}

func (c configValidated) Pattern() secrets.Pattern {
	return c.pattern
}
