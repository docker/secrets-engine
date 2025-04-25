package main

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

type Engine struct {
	plugins []pluginRegistration
}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) GetSecret(id ID) (Envelope, error) {
	var errs []error
	for _, plugin := range e.plugins {
		if !id.Match(plugin.pattern) {
			continue
		}

		envelope, err := plugin.provider.GetSecret(id)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// we use the first matching, successful registration to resolve the secret.
		envelope.Source = plugin.name
		return envelope, nil
	}

	var err error
	if len(errs) == 0 {
		err = ErrNotFound
	} else {
		err = errors.Join(errs...)
	}
	return Envelope{ID: id, ResolvedAt: time.Now()}, err
}

type pluginRegistration struct {
	name     string
	version  string
	pattern  string
	provider SecretProvider
}

func (e *Engine) Register(name, version, pattern string, provider SecretProvider) error {
	if slices.ContainsFunc(e.plugins, func(pr pluginRegistration) bool {
		return pr.name == name
	}) {
		return fmt.Errorf("provider name %q already registered", name)
	}

	e.plugins = append(e.plugins, pluginRegistration{
		name:     name,
		pattern:  pattern,
		provider: provider,
	})

	return nil
}
