// Copyright 2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flock

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"
)

type backoff struct {
	initial    time.Duration
	max        time.Duration
	multiplier float64
	jitter     float64
	rand       func() float64
	current    time.Duration
}

const (
	retryInitialDelay = 10 * time.Millisecond
	retryMaxDelay     = 100 * time.Millisecond
)

func newBackoff() *backoff {
	return &backoff{
		initial:    retryInitialDelay,
		max:        retryMaxDelay,
		multiplier: 1.5,
		jitter:     0.5,
		rand:       rand.Float64,
	}
}

func (b *backoff) next() time.Duration {
	upper := max(b.max, 0)
	if b.current <= 0 {
		b.current = max(b.initial, 0)
	}
	cur := min(b.current, upper)

	j := b.jitter
	if !(j >= 0) {
		j = 0
	}
	j = min(j, 1)

	r := 0.5
	if b.rand != nil {
		r = b.rand()
	}
	if !(r >= 0) {
		r = 0
	}
	r = min(r, 1)

	delta := j * float64(cur)
	d := clampDuration(float64(cur)-delta+r*2*delta, upper)

	m := b.multiplier
	if !(m >= 1) {
		m = 1
	}
	b.current = max(cur, clampDuration(float64(cur)*m, upper))
	return d
}

func clampDuration(f float64, upper time.Duration) time.Duration {
	if !(f > 0) {
		return 0
	}
	if f >= float64(upper) {
		return upper
	}
	return time.Duration(f)
}

func retry[T any](ctx context.Context, b *backoff, op func() (T, error)) (T, error) {
	for {
		v, err := op()
		if err == nil {
			return v, nil
		}
		t := time.NewTimer(b.next())
		select {
		case <-ctx.Done():
			t.Stop()
			var zero T
			return zero, errors.Join(err, context.Cause(ctx))
		case <-t.C:
		}
	}
}
