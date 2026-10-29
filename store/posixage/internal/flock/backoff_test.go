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
	"math"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixedRand(r float64) func() float64 {
	return func() float64 { return r }
}

func TestBackoffNext(t *testing.T) {
	t.Run("grows by the multiplier and caps at max", func(t *testing.T) {
		b := newBackoff()
		b.rand = fixedRand(0.5)

		want := []time.Duration{
			10 * time.Millisecond,
			15 * time.Millisecond,
			22500 * time.Microsecond,
			33750 * time.Microsecond,
			50625 * time.Microsecond,
			75937500 * time.Nanosecond,
			100 * time.Millisecond,
			100 * time.Millisecond,
		}
		for i, w := range want {
			assert.Equal(t, w, b.next(), "step %d", i)
		}
	})

	t.Run("lowest jitter halves the delay", func(t *testing.T) {
		b := newBackoff()
		b.rand = fixedRand(0)
		assert.Equal(t, 5*time.Millisecond, b.next())
		assert.Equal(t, 7500*time.Microsecond, b.next())
	})

	t.Run("highest jitter never exceeds max", func(t *testing.T) {
		b := newBackoff()
		b.rand = fixedRand(1)
		assert.Equal(t, 15*time.Millisecond, b.next())
		for range 20 {
			assert.LessOrEqual(t, b.next(), retryMaxDelay)
		}
		assert.Equal(t, retryMaxDelay, b.next())
	})

	t.Run("default random source stays within bounds", func(t *testing.T) {
		b := newBackoff()
		prev := time.Duration(0)
		for range 1000 {
			cur := b.current
			d := b.next()
			assert.GreaterOrEqual(t, d, time.Duration(0))
			assert.LessOrEqual(t, d, retryMaxDelay)
			assert.GreaterOrEqual(t, b.current, prev)
			assert.GreaterOrEqual(t, b.current, cur)
			prev = b.current
		}
	})

	t.Run("degenerate configuration does not panic", func(t *testing.T) {
		cases := []*backoff{
			{},
			{initial: -time.Second, max: -time.Second},
			{initial: time.Second, max: time.Millisecond, multiplier: math.NaN(), jitter: math.NaN(), rand: fixedRand(math.NaN())},
			{initial: math.MaxInt64, max: math.MaxInt64, multiplier: math.Inf(1), jitter: math.Inf(1), rand: fixedRand(math.Inf(1))},
			{initial: time.Millisecond, max: time.Second, multiplier: -2, jitter: -1, rand: fixedRand(-1)},
		}
		for _, b := range cases {
			for range 10 {
				d := b.next()
				assert.GreaterOrEqual(t, d, time.Duration(0))
				assert.LessOrEqual(t, d, max(b.max, 0))
			}
		}
	})
}

func FuzzBackoffNext(f *testing.F) {
	f.Add(int64(10*time.Millisecond), int64(100*time.Millisecond), 1.5, 0.5, 0.5, uint8(16))
	f.Add(int64(0), int64(0), 0.0, 0.0, 0.0, uint8(1))
	f.Add(int64(-1), int64(-1), -1.0, -1.0, -1.0, uint8(4))
	f.Add(int64(math.MaxInt64), int64(math.MaxInt64), math.Inf(1), 1.0, 1.0, uint8(64))
	f.Add(int64(1), int64(math.MaxInt64), 2.0, 1.0, 0.999999, uint8(255))
	f.Add(int64(time.Second), int64(time.Millisecond), math.NaN(), math.NaN(), math.NaN(), uint8(8))

	f.Fuzz(func(t *testing.T, initial, maxDelay int64, multiplier, jitter, r float64, steps uint8) {
		b := &backoff{
			initial:    time.Duration(initial),
			max:        time.Duration(maxDelay),
			multiplier: multiplier,
			jitter:     jitter,
			rand:       fixedRand(r),
		}
		upper := max(b.max, 0)
		prev := time.Duration(0)
		for i := range int(steps) {
			d := b.next()
			if d < 0 || d > upper {
				t.Fatalf("step %d: delay %v outside [0, %v]", i, d, upper)
			}
			if b.current < prev {
				t.Fatalf("step %d: interval shrank from %v to %v", i, prev, b.current)
			}
			if b.current > upper {
				t.Fatalf("step %d: interval %v above max %v", i, b.current, upper)
			}
			if i > 0 && jitter == 0 && prev < 1<<53 && d != prev {
				t.Fatalf("step %d: delay %v without jitter differs from interval %v", i, d, prev)
			}
			prev = b.current
		}
	})
}

var errAttempt = errors.New("attempt failed")

func TestRetry(t *testing.T) {
	t.Run("returns immediately on first success", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			calls := 0
			start := time.Now()
			v, err := retry(t.Context(), newBackoff(), func() (int, error) {
				calls++
				return 42, nil
			})
			require.NoError(t, err)
			assert.Equal(t, 42, v)
			assert.Equal(t, 1, calls)
			assert.Zero(t, time.Since(start))
		})
	})

	t.Run("waits the backoff delay between attempts", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			b := newBackoff()
			b.rand = fixedRand(0.5)
			calls := 0
			start := time.Now()
			v, err := retry(t.Context(), b, func() (string, error) {
				calls++
				if calls < 4 {
					return "", errAttempt
				}
				return "ok", nil
			})
			require.NoError(t, err)
			assert.Equal(t, "ok", v)
			assert.Equal(t, 4, calls)
			assert.Equal(t, 47500*time.Microsecond, time.Since(start))
		})
	})

	t.Run("stops at the context deadline with both errors", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			b := newBackoff()
			b.rand = fixedRand(0.5)
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()

			calls := 0
			start := time.Now()
			v, err := retry(ctx, b, func() (*int, error) {
				calls++
				n := calls
				return &n, errAttempt
			})
			require.ErrorIs(t, err, errAttempt)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Nil(t, v)
			assert.Equal(t, 4, calls)
			assert.Equal(t, 50*time.Millisecond, time.Since(start))
		})
	})

	t.Run("canceled context runs the operation once", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			cause := errors.New("shutting down")
			cancel(cause)

			calls := 0
			_, err := retry(ctx, newBackoff(), func() (int, error) {
				calls++
				return 0, errAttempt
			})
			require.ErrorIs(t, err, errAttempt)
			require.ErrorIs(t, err, cause)
			assert.Equal(t, 1, calls)
		})
	})
}

func FuzzRetry(f *testing.F) {
	f.Add(uint8(0), int64(time.Second))
	f.Add(uint8(3), int64(50*time.Millisecond))
	f.Add(uint8(40), int64(time.Millisecond))
	f.Add(uint8(255), int64(time.Minute))

	f.Fuzz(func(t *testing.T, failures uint8, timeout int64) {
		deadline := time.Duration(max(timeout, 0))

		shadow := newBackoff()
		shadow.rand = fixedRand(0.5)
		var wantElapsed time.Duration
		wantCalls := 1
		for range int(failures) {
			d := shadow.next()
			if wantElapsed+d == deadline {
				t.Skip("timer and deadline fire at the same instant")
			}
			if wantElapsed+d > deadline {
				break
			}
			wantElapsed += d
			wantCalls++
		}
		succeeds := wantCalls == int(failures)+1

		synctest.Test(t, func(t *testing.T) {
			b := newBackoff()
			b.rand = fixedRand(0.5)
			ctx, cancel := context.WithTimeout(t.Context(), deadline)
			defer cancel()

			calls := 0
			start := time.Now()
			_, err := retry(ctx, b, func() (struct{}, error) {
				calls++
				if calls > int(failures) {
					return struct{}{}, nil
				}
				return struct{}{}, errAttempt
			})
			elapsed := time.Since(start)

			if succeeds {
				require.NoError(t, err)
				assert.Equal(t, wantElapsed, elapsed)
			} else {
				require.ErrorIs(t, err, errAttempt)
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Equal(t, deadline, elapsed)
			}
			assert.Equal(t, wantCalls, calls)
		})
	})
}
