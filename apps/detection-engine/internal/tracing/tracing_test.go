package tracing

import "testing"

// TestEndpointFromEnvHasNoDefault: the endpoint used to default to
// otel-collector.observability.svc:4317, so a service started outside
// Kubernetes dialled a name that does not exist, forever.
func TestEndpointFromEnvHasNoDefault(t *testing.T) {
	cases := []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{}, ""},
		{map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "  "}, ""},
		{map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "collector:4317"}, "collector:4317"},
		{map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://traces:4317"}, "http://traces:4317"},
		// The signal-specific variable wins, as the specification says.
		{map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "collector:4317",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "traces:4317"}, "traces:4317"},
	}
	for _, tc := range cases {
		if got := EndpointFromEnv(func(k string) string { return tc.env[k] }); got != tc.want {
			t.Errorf("EndpointFromEnv(%v) = %q, want %q", tc.env, got, tc.want)
		}
	}
}
