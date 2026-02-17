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

package telemetry

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"github.com/docker/secrets-engine/x/logging"
)

type ShutdownFunc func(ctx context.Context)

// InitializeOTel sets up OTEL with meter/metrics and tracer providers
func InitializeOTel(ctx context.Context, endpoint string) (ShutdownFunc, error) {
	logger, err := logging.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	otel.SetErrorHandler(&errorhandler{logger: logger})
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	res := newResource(ctx)

	var secure bool
	endpoint, secure = sanitizeEndpoint(endpoint)
	tracerProvider := createTraceProvider(ctx, res, endpoint, secure)
	metricsProvider := createMetricProvider(ctx, res, endpoint, secure)
	cleanup := func(ctx context.Context) {
		if err := tracerProvider.Shutdown(ctx); err != nil {
			logger.Warnf("Tracer provider did not shut down cleanly: %s", err)
		}
		if err := metricsProvider.Shutdown(ctx); err != nil {
			logger.Warnf("Metrics provider did not shut down cleanly: %s", err)
		}
	}
	otel.SetTracerProvider(tracerProvider)
	otel.SetMeterProvider(metricsProvider)
	return cleanup, nil
}

func createMetricProvider(ctx context.Context, res *resource.Resource, endpoint string, secure bool) *sdkmetric.MeterProvider {
	expOpts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(endpoint),
	}
	if !secure {
		expOpts = append(expOpts, otlpmetricgrpc.WithInsecure())
	}

	exp, err := otlpmetricgrpc.New(ctx, expOpts...)
	if err != nil {
		otel.Handle(err)
		return nil
	}
	return sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(
			exp,
			sdkmetric.WithTimeout(5*time.Second),
			sdkmetric.WithInterval(30*time.Second),
		)),
		sdkmetric.WithResource(res),
	)
}

func createTraceProvider(ctx context.Context, res *resource.Resource, endpoint string, secure bool) *sdktrace.TracerProvider {
	expOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(endpoint),
	}
	if !secure {
		expOpts = append(expOpts, otlptracegrpc.WithInsecure())
	}

	exp, err := otlptracegrpc.New(ctx, expOpts...)
	if err != nil {
		otel.Handle(err)
		return nil
	}
	return sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
}

func newResource(ctx context.Context) *resource.Resource {
	opts := []resource.Option{
		resource.WithFromEnv(),
		resource.WithOS(),
		resource.WithHost(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String("secrets-engine"),
		),
	}
	res, err := resource.New(ctx, opts...)
	if err != nil {
		otel.Handle(err)
	}
	return res
}

type errorhandler struct {
	logger logging.Logger
}

func (eh *errorhandler) Handle(err error) {
	eh.logger.Warnf("otel: %s", err)
}

func sanitizeEndpoint(endpoint string) (string, bool) {
	u, err := url.Parse(endpoint)
	if err != nil {
		otel.Handle(fmt.Errorf("invalid otel endpoint '%s': %s", endpoint, err))
		return "", false
	}

	var secure bool
	switch u.Scheme {
	// TODO: add support for OTEL endpoints through sockets
	// case "unix":
	//	endpoint = unixSocketEndpoint(u)
	case "https":
		secure = true
		fallthrough
	case "http":
		endpoint = path.Join(u.Host, u.Path)
	}
	return endpoint, secure
}
