// Copyright 2025-2026 Docker, Inc.
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

package testhelper

import (
	"context"
	"errors"
	"math/rand"
	"slices"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/telemetry"
)

func WaitForErrorWithTimeout(in <-chan error) error {
	val, err := WaitForWithExplicitTimeoutV(in, 2*time.Second)
	if err != nil {
		return err
	}
	return val
}

func WaitForClosedWithTimeout(in <-chan struct{}) error {
	select {
	case <-in:
		return nil
	case <-time.After(4 * time.Second):
		return errors.New("timeout")
	}
}

func WaitForWithTimeoutV[T any](ch <-chan T) (T, error) {
	return WaitForWithExplicitTimeoutV(ch, 2*time.Second)
}

func WaitForWithExplicitTimeoutV[T any](ch <-chan T, timeout time.Duration) (T, error) {
	var zero T
	select {
	case val, ok := <-ch:
		if !ok {
			return zero, errors.New("channel closed")
		}
		return val, nil
	case <-time.After(timeout):
		return zero, errors.New("timeout")
	}
}

// RandomShortSocketName creates a socket name string that avoids common pitfalls in tests.
// There are a bunch of opposing problems in unit tests with sockets:
// Ideally, we'd like to use t.TmpDir+something.sock -> too long socket name
// We can't just use local short file name -> clashes when running tests in parallel
// We can't use t.ChDir + short name -> t.ChDir does not allow t.Parallel
// -> we use a short local but randomized socket path
func RandomShortSocketName() string {
	return randString(6) + ".sock"
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func TestLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewDefaultLogger(t.Name())
}

var _ telemetry.Tracker = &testTracker{}

type TestTracker interface {
	telemetry.Tracker
	GetQueue() []any
}

type testTracker struct {
	Queue []any
	m     sync.Mutex
}

func NewTestTracker() TestTracker {
	return &testTracker{}
}

func (t *testTracker) GetQueue() []any {
	t.m.Lock()
	defer t.m.Unlock()
	return t.Queue
}

func (t *testTracker) Notify(error, ...interface{}) {
}

func (t *testTracker) TrackEvent(event any) {
	t.m.Lock()
	defer t.m.Unlock()
	t.Queue = append(t.Queue, event)
}

func SetupTelemetry(t *testing.T) (*tracetest.SpanRecorder, *metric.ManualReader) {
	t.Helper()

	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := trace.NewTracerProvider(
		trace.WithSpanProcessor(spanRecorder),
	)
	otel.SetTracerProvider(tracerProvider)

	reader := metric.NewManualReader()
	meterProvider := metric.NewMeterProvider(
		metric.WithReader(reader),
	)
	otel.SetMeterProvider(meterProvider)

	t.Cleanup(func() {
		otel.SetTracerProvider(trace.NewTracerProvider())
		otel.SetMeterProvider(metric.NewMeterProvider())
	})

	return spanRecorder, reader
}

func FilterMetrics(rm metricdata.ResourceMetrics, name string) []metricdata.Metrics {
	var filtered []metricdata.Metrics
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				filtered = append(filtered, m)
			}
		}
	}
	return filtered
}

func TestLoggerCtx(t *testing.T) context.Context {
	t.Helper()
	return logging.WithLogger(t.Context(), logging.NewDefaultLogger(t.Name()))
}

var _ secrets.Resolver = &MockResolver{}

type MockResolver struct {
	Store map[secrets.ID]string
}

func (m MockResolver) GetSecrets(_ context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	var result []secrets.Envelope
	for id, v := range m.Store {
		if pattern.Match(id) {
			result = append(result, secrets.Envelope{ID: id, Value: []byte(v)})
		}
	}
	slices.SortFunc(result, func(a, b secrets.Envelope) int {
		switch {
		case a.ID.String() < b.ID.String():
			return -1
		case a.ID.String() > b.ID.String():
			return 1
		default:
			return 0
		}
	})
	return result, nil
}
