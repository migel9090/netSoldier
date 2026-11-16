package tracing

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// EndpointFromEnv returns the OTLP endpoint traces go to, from the standard
// variables (the traces-specific one wins), or "" when none is set. There is
// no default: an exporter dials in the background, and the in-cluster
// collector name the service used to assume was retried forever wherever it
// does not exist.
func EndpointFromEnv(getenv func(string) string) string {
	for _, key := range []string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT"} {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

// Init exports traces to endpoint over OTLP/gRPC. The endpoint is either the
// specification's URL form, whose scheme decides TLS (http://collector:4317,
// https://…), or the bare host:port the deployments have always used, which
// stays plaintext. The other OTEL_EXPORTER_OTLP_* variables (headers,
// timeout, certificates) and OTEL_TRACES_SAMPLER are read by the SDK.
func Init(ctx context.Context, serviceName, endpoint string) (*sdktrace.TracerProvider, error) {
	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(endpoint), otlptracegrpc.WithInsecure()}
	if u, err := url.Parse(endpoint); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		opts = []otlptracegrpc.Option{otlptracegrpc.WithEndpointURL(endpoint)}
	}
	exp, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create otlp exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
		)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp, nil
}
