package secrets

import (
	"context"
	"sync"
)

// Restricted controls access to a set of secrets.
//
// By default, it allows access to no secrets but
// can be modified safely from other threads.
type Restricted struct {
	allowed map[string]struct{}
	mu      sync.Mutex
	next    Resolver
}

func NewRestricted(resolver Resolver, allowed ...ID) *Restricted {
	return &Restricted{
		allowed: allowList(allowed...),
		next:    resolver,
	}
}

func (r *Restricted) Allow(allowed ...ID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, id := range allowed {
		r.allowed[id.String()] = struct{}{}
	}
}

func (r *Restricted) GetSecret(ctx context.Context, request Request) (Envelope, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.allowed[request.ID.String()]; !ok {
		return Envelope{ID: request.ID, Error: ErrAccessDenied.Error()}, ErrAccessDenied
	}

	return r.next.GetSecret(ctx, request)
}

func allowList(allowed ...ID) map[string]struct{} {
	m := make(map[string]struct{}, len(allowed))
	for _, v := range allowed {
		m[v.String()] = struct{}{}
	}

	return m
}
