// ABOUTME: Tests that every audited request is also counted on the optional metrics endpoint.
// ABOUTME: Denials, upstream errors and the nil collector are covered.
package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/metrics"
)

// scrapeCollector renders the collector's exposition text.
func scrapeCollector(t *testing.T, collector *metrics.Collector) string {
	t.Helper()
	rec := httptest.NewRecorder()
	collector.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	return rec.Body.String()
}

func TestMetricsCountAllowedAndDeniedRequests(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1}`))
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, "glpat-secret"))
	collector := metrics.New(time.Unix(0, 0))
	exec.Metrics = collector

	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), newFakeResponder())
	// Not on the allowlist: denied before anything is sent upstream.
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/admin/users", ""), newFakeResponder())

	body := scrapeCollector(t, collector)
	for _, want := range []string{
		`zenfra_vcs_connector_requests_total{lane="interactive",decision="allow"} 1`,
		`zenfra_vcs_connector_requests_total{lane="interactive",decision="deny"} 1`,
		"zenfra_vcs_connector_request_duration_seconds_count 2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	// A denial is not an error: it is the policy working as configured.
	if !strings.Contains(body, "zenfra_vcs_connector_request_errors_total 1") {
		t.Errorf("only the denial should count as an error code:\n%s", body)
	}
}

func TestMetricsCountUpstreamFailures(t *testing.T) {
	// An endpoint nothing listens on: the upstream call cannot connect.
	exec, _ := newExecutor(t, "http://127.0.0.1:1", newSecretFile(t, "glpat-secret"))
	collector := metrics.New(time.Unix(0, 0))
	exec.Metrics = collector

	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), newFakeResponder())

	body := scrapeCollector(t, collector)
	if !strings.Contains(body, "zenfra_vcs_connector_request_errors_total 1") {
		t.Errorf("an unreachable upstream must be counted:\n%s", body)
	}
	if !strings.Contains(body,
		`zenfra_vcs_connector_requests_total{lane="interactive",decision="allow"} 1`) {
		t.Errorf("the request was policy-allowed and must be counted as such:\n%s", body)
	}
}

func TestExecutorWorksWithoutMetrics(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	exec, buf := newExecutor(t, stub.srv.URL, newSecretFile(t, "glpat-secret"))
	exec.Metrics = nil

	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), newFakeResponder())
	if !strings.Contains(buf.String(), `"decision":"allow"`) {
		t.Fatalf("the audit record must be written with no collector wired:\n%s", buf.String())
	}
}
