// ABOUTME: Optional Prometheus endpoint for the connector: stream, request and denial counters.
// ABOUTME: Renders the text exposition format from the standard library — no client dependency.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Metric names, prefixed to sit beside the gateway's own tunnel metrics.
const (
	nameStreams   = "zenfra_vcs_connector_tunnel_streams"
	nameConnects  = "zenfra_vcs_connector_stream_connects_total"
	nameRequests  = "zenfra_vcs_connector_requests_total"
	nameErrors    = "zenfra_vcs_connector_request_errors_total"
	nameDuration  = "zenfra_vcs_connector_request_duration_seconds"
	nameStartedAt = "zenfra_vcs_connector_start_time_seconds"
)

// lanes and decisions are the complete label vocabulary. Pre-creating every
// series keeps the counter map immutable, so it needs no lock and cannot grow.
var (
	lanes     = []string{"interactive", "bulk"}
	decisions = []string{"allow", "deny"}
)

// Collector counts connector activity. Every method is nil-safe: the endpoint is
// optional, and a connector running without it must behave identically.
type Collector struct {
	streams  atomic.Int64
	connects atomic.Uint64
	errors   atomic.Uint64
	// requests is keyed "lane|decision"; the key set is fixed at construction.
	requests map[string]*atomic.Uint64
	// elapsed accumulates request duration in nanoseconds, rendered as a summary.
	elapsed atomic.Int64
	count   atomic.Uint64
	// startedAt is a fixed timestamp so uptime is derivable without a clock here.
	startedAt time.Time
}

// New creates a collector. startedAt is passed in rather than read so the caller
// owns the only clock read.
func New(startedAt time.Time) *Collector {
	c := &Collector{
		requests:  make(map[string]*atomic.Uint64, len(lanes)*len(decisions)),
		startedAt: startedAt,
	}
	for _, lane := range lanes {
		for _, decision := range decisions {
			c.requests[key(lane, decision)] = new(atomic.Uint64)
		}
	}
	return c
}

func key(lane, decision string) string { return lane + "|" + decision }

// StreamOpened records an established tunnel stream.
func (c *Collector) StreamOpened() {
	if c == nil {
		return
	}
	c.streams.Add(1)
	c.connects.Add(1)
}

// StreamClosed records a tunnel stream that ended.
func (c *Collector) StreamClosed() {
	if c == nil {
		return
	}
	c.streams.Add(-1)
}

// Request records one tunneled request. errCode is empty on success.
func (c *Collector) Request(lane, decision, errCode string, elapsed time.Duration) {
	if c == nil {
		return
	}
	if counter, ok := c.requests[key(lane, decision)]; ok {
		counter.Add(1)
	}
	if errCode != "" {
		c.errors.Add(1)
	}
	c.elapsed.Add(int64(elapsed))
	c.count.Add(1)
}

// Handler serves the metrics in Prometheus text exposition format.
func (c *Collector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = io.WriteString(w, c.exposition())
	})
}

// exposition renders every family. Ordering is deterministic so a diff of two
// scrapes is readable.
func (c *Collector) exposition() string {
	lines := []string{
		help(nameStreams, "gauge", "Live tunnel streams to the Zenfra gateway."),
		fmt.Sprintf("%s %d", nameStreams, c.streams.Load()),
		help(nameConnects, "counter", "Tunnel streams established since start."),
		fmt.Sprintf("%s %d", nameConnects, c.connects.Load()),
		help(nameRequests, "counter", "Tunneled requests by lane and policy decision."),
	}
	series := make([]string, 0, len(c.requests))
	for _, lane := range lanes {
		for _, decision := range decisions {
			series = append(series, fmt.Sprintf("%s{lane=%q,decision=%q} %d",
				nameRequests, lane, decision, c.requests[key(lane, decision)].Load()))
		}
	}
	sort.Strings(series)
	lines = append(lines, series...)

	lines = append(lines,
		help(nameErrors, "counter", "Tunneled requests that failed with an error code."),
		fmt.Sprintf("%s %d", nameErrors, c.errors.Load()),
		help(nameDuration, "summary", "Tunneled request duration."),
		fmt.Sprintf("%s_sum %g", nameDuration, time.Duration(c.elapsed.Load()).Seconds()),
		fmt.Sprintf("%s_count %d", nameDuration, c.count.Load()),
		help(nameStartedAt, "gauge", "Start time of the connector process."),
		fmt.Sprintf("%s %d", nameStartedAt, c.startedAt.Unix()),
	)
	return strings.Join(lines, "\n") + "\n"
}

// help renders the HELP and TYPE preamble of one metric family.
func help(name, metricType, text string) string {
	return fmt.Sprintf("# HELP %s %s\n# TYPE %s %s", name, text, name, metricType)
}
