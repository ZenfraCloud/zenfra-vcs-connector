// ABOUTME: Tests the connector's optional Prometheus endpoint: exposition shape and counters.
// ABOUTME: Also asserts the endpoint is nil-safe and never renders a credential-bearing label.
package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scrape(t *testing.T, c *Collector) string {
	t.Helper()
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("content type = %q, want text/plain", got)
	}
	return rec.Body.String()
}

func TestExpositionHasEveryFamilyTyped(t *testing.T) {
	body := scrape(t, New(time.Unix(1700000000, 0)))

	for _, name := range []string{
		nameStreams, nameConnects, nameRequests, nameErrors, nameDuration, nameStartedAt,
	} {
		if !strings.Contains(body, "# HELP "+name+" ") {
			t.Errorf("missing HELP for %s", name)
		}
		if !strings.Contains(body, "# TYPE "+name+" ") {
			t.Errorf("missing TYPE for %s", name)
		}
	}
	// Every series exists before anything happens, so a scrape never changes shape.
	for _, want := range []string{
		`zenfra_vcs_connector_requests_total{lane="interactive",decision="allow"} 0`,
		`zenfra_vcs_connector_requests_total{lane="bulk",decision="deny"} 0`,
		"zenfra_vcs_connector_tunnel_streams 0",
		"zenfra_vcs_connector_request_duration_seconds_count 0",
		"zenfra_vcs_connector_start_time_seconds 1700000000",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing sample %q in:\n%s", want, body)
		}
	}
}

func TestCountersRecordActivity(t *testing.T) {
	c := New(time.Unix(0, 0))

	c.StreamOpened()
	c.StreamOpened()
	c.StreamClosed()
	c.Request("interactive", "allow", "", 250*time.Millisecond)
	c.Request("interactive", "deny", "policy_denied", 0)
	c.Request("bulk", "allow", "upstream_timeout", 750*time.Millisecond)

	body := scrape(t, c)
	for _, want := range []string{
		"zenfra_vcs_connector_tunnel_streams 1",
		"zenfra_vcs_connector_stream_connects_total 2",
		`zenfra_vcs_connector_requests_total{lane="interactive",decision="allow"} 1`,
		`zenfra_vcs_connector_requests_total{lane="interactive",decision="deny"} 1`,
		`zenfra_vcs_connector_requests_total{lane="bulk",decision="allow"} 1`,
		"zenfra_vcs_connector_request_errors_total 2",
		"zenfra_vcs_connector_request_duration_seconds_sum 1",
		"zenfra_vcs_connector_request_duration_seconds_count 3",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing sample %q in:\n%s", want, body)
		}
	}
}

func TestUnknownLabelsAreDropped(t *testing.T) {
	c := New(time.Unix(0, 0))
	// A caller passing something outside the vocabulary must not create a series:
	// the label set is what keeps the endpoint's cardinality fixed.
	c.Request("smuggled", "allow", "", time.Second)
	c.Request("interactive", "maybe", "", time.Second)

	body := scrape(t, c)
	if strings.Contains(body, "smuggled") || strings.Contains(body, "maybe") {
		t.Fatalf("unknown label leaked into the exposition:\n%s", body)
	}
	// The duration summary still counts them: they were real requests.
	if !strings.Contains(body, "zenfra_vcs_connector_request_duration_seconds_count 2") {
		t.Errorf("duration count missing in:\n%s", body)
	}
}

func TestNilCollectorIsSafe(t *testing.T) {
	var c *Collector
	c.StreamOpened()
	c.StreamClosed()
	c.Request("interactive", "allow", "", time.Second)
}
