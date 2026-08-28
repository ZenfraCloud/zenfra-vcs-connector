// ABOUTME: Tests for the connection manager — register→JWT→dial, lane counts, backoff, refresh.
// ABOUTME: A stub control plane serves register, refresh and the tunnel upgrade together.
package connect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/metrics"
)

// stubPlane is a control plane serving registration, refresh and tunnel upgrades.
type stubPlane struct {
	srv *httptest.Server

	mu sync.Mutex
	// registerStatus is consumed one entry per call; 0 or exhausted means 201.
	registerStatus []int
	// tunnelStatus rejects upgrades with the given statuses, one per call.
	tunnelStatus []int
	// refreshStatus is consumed one entry per call; 0 or exhausted means 200.
	refreshStatus []int
	registers     int
	refreshes     int
	// tokenTTL is how long minted tokens stay valid.
	tokenTTL time.Duration
	minted   int
	lanes    []Lane
	tokens   []string
	conns    []*websocket.Conn
	accepted chan *websocket.Conn
}

func newStubPlane(t *testing.T) *stubPlane {
	t.Helper()
	p := &stubPlane{tokenTTL: time.Hour, accepted: make(chan *websocket.Conn, 32)}
	upgrader := websocket.Upgrader{EnableCompression: false}

	mux := http.NewServeMux()
	mux.HandleFunc(registerPath, func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		p.registers++
		status := http.StatusCreated
		if len(p.registerStatus) > 0 {
			status, p.registerStatus = p.registerStatus[0], p.registerStatus[1:]
		}
		p.mu.Unlock()
		if status != http.StatusCreated {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "denied", "message": "no"})
			return
		}
		p.writeToken(w, http.StatusCreated)
	})
	mux.HandleFunc(refreshPath, func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		p.refreshes++
		status := http.StatusOK
		if len(p.refreshStatus) > 0 {
			status, p.refreshStatus = p.refreshStatus[0], p.refreshStatus[1:]
		}
		p.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "denied", "message": "no"})
			return
		}
		p.writeToken(w, http.StatusOK)
	})
	mux.HandleFunc(tunnelPath, func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		reject := 0
		if len(p.tunnelStatus) > 0 {
			reject, p.tunnelStatus = p.tunnelStatus[0], p.tunnelStatus[1:]
		}
		p.mu.Unlock()
		if reject != 0 {
			w.WriteHeader(reject)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "unauthenticated", "message": "revoked jti",
			})
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.lanes = append(p.lanes, Lane(r.URL.Query().Get("lane")))
		p.tokens = append(p.tokens, r.Header.Get("Authorization"))
		p.conns = append(p.conns, conn)
		p.mu.Unlock()
		p.accepted <- conn
	})

	p.srv = httptest.NewServer(mux)
	t.Cleanup(func() {
		p.mu.Lock()
		conns := append([]*websocket.Conn(nil), p.conns...)
		p.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
		p.srv.Close()
	})
	return p
}

func (p *stubPlane) writeToken(w http.ResponseWriter, status int) {
	p.mu.Lock()
	p.minted++
	token := "jwt-" + string(rune('0'+p.minted%10))
	ttl := p.tokenTTL
	p.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"connector_id": "c1",
		"instance_id":  "i1",
		"token":        token,
		"expires_at":   time.Now().Add(ttl),
		"endpoint":     "https://gitlab.internal",
		"vendor":       "gitlab",
	})
}

// rejectRegisters scripts one status per registration call.
func (p *stubPlane) rejectRegisters(statuses ...int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.registerStatus = append(p.registerStatus, statuses...)
}

// rejectUpgrades scripts one status per tunnel upgrade.
func (p *stubPlane) rejectUpgrades(statuses ...int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tunnelStatus = append(p.tunnelStatus, statuses...)
}

// setTokenTTL sets how long minted tokens remain valid.
func (p *stubPlane) setTokenTTL(ttl time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenTTL = ttl
}

func (p *stubPlane) setRefreshStatus(statuses ...int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshStatus = statuses
}

func (p *stubPlane) counts() (registers, refreshes int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.registers, p.refreshes
}

func (p *stubPlane) laneCounts() map[Lane]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[Lane]int{}
	for _, lane := range p.lanes {
		out[lane]++
	}
	return out
}

func (p *stubPlane) presentedTokens() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.tokens...)
}

// waitAccepted waits until n connections have been accepted.
func (p *stubPlane) waitAccepted(t *testing.T, n int) {
	t.Helper()
	for range n {
		select {
		case <-p.accepted:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d connections were accepted", len(p.presentedTokens()), n)
		}
	}
}

// newTestManager wires a manager against the stub plane with fast backoff.
func newTestManager(t *testing.T, p *stubPlane, interactive int) *Manager {
	t.Helper()
	cfg := testConfig(t)
	cfg.GatewayURL = p.srv.URL
	cfg.InteractiveConnections = interactive

	dialer, err := NewDialer(cfg, "sha256:policy", func(context.Context, *Request, *Responder) {}, testLogger())
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	m := NewManager(cfg, NewClient(cfg.GatewayURL, nil), dialer, "test", testLogger())
	m.BackoffBase = time.Millisecond
	m.BackoffCap = 5 * time.Millisecond
	return m
}

// run starts the manager and returns a stop func plus its result channel.
func run(t *testing.T, m *Manager) (stop context.CancelFunc, result chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	result = make(chan error, 1)
	done := make(chan struct{})
	go func() {
		result <- m.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run() did not return after cancellation")
		}
	})
	return cancel, result
}

func TestBackoffIsCappedAndJittered(t *testing.T) {
	const base, capped = time.Second, 30 * time.Second
	for attempt := range 10 {
		want := min(base<<attempt, capped)
		if attempt > 30 { // guard against shift overflow in the test itself
			want = capped
		}
		for range 50 {
			got := Backoff(attempt, base, capped)
			if got < want/2 || got > want {
				t.Fatalf("Backoff(%d) = %v, want within [%v, %v]", attempt, got, want/2, want)
			}
		}
	}
}

func TestBackoffNeverExceedsTheCap(t *testing.T) {
	for _, attempt := range []int{20, 40, 63, 64, 200} {
		for range 20 {
			if got := Backoff(attempt, time.Second, 30*time.Second); got < 15*time.Second || got > 30*time.Second {
				t.Fatalf("Backoff(%d) = %v, want within [15s, 30s]", attempt, got)
			}
		}
	}
}

func TestBackoffIsActuallyJittered(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 50 {
		seen[Backoff(5, time.Second, 30*time.Second)] = true
	}
	if len(seen) < 2 {
		t.Error("Backoff() returned a constant delay; a thundering herd would not be spread out")
	}
}

func TestManagerOpensInteractiveLanesPlusOneBulk(t *testing.T) {
	p := newStubPlane(t)
	m := newTestManager(t, p, 2)
	run(t, m)

	p.waitAccepted(t, 3)
	lanes := p.laneCounts()
	if lanes[LaneInteractive] != 2 || lanes[LaneBulk] != 1 {
		t.Errorf("lanes = %v, want 2 interactive and 1 bulk", lanes)
	}
	// One instance shares one token, so registration happens once for all lanes.
	if registers, _ := p.counts(); registers != 1 {
		t.Errorf("registers = %d, want 1", registers)
	}
	for _, token := range p.presentedTokens() {
		if token == "" || token == "Bearer " {
			t.Errorf("a connection dialed without a token: %q", token)
		}
	}
}

func TestManagerReconnectsAfterStreamLoss(t *testing.T) {
	p := newStubPlane(t)
	m := newTestManager(t, p, 1)
	run(t, m)

	p.waitAccepted(t, 2)
	p.mu.Lock()
	first := p.conns[0]
	p.mu.Unlock()
	_ = first.Close()

	// The dropped lane must come back on its own.
	p.waitAccepted(t, 1)
}

func TestManagerStopsOnTerminalRegistrationFailure(t *testing.T) {
	p := newStubPlane(t)
	p.rejectRegisters(http.StatusUnauthorized)
	m := newTestManager(t, p, 1)
	_, result := run(t, m)

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("Run() error = nil, want the rejected bootstrap token to be fatal")
		}
		if IsRetryable(err) {
			t.Errorf("Run() returned a retryable error %v; a rejected token must stop the connector", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() kept retrying a rejected bootstrap token instead of exiting")
	}
	if registers, _ := p.counts(); registers > 2 {
		t.Errorf("registers = %d, want no retry loop on a terminal rejection", registers)
	}
}

func TestManagerRetriesRetryableRegistrationFailure(t *testing.T) {
	p := newStubPlane(t)
	p.rejectRegisters(http.StatusServiceUnavailable)
	m := newTestManager(t, p, 1)
	run(t, m)

	p.waitAccepted(t, 2)
	if registers, _ := p.counts(); registers < 2 {
		t.Errorf("registers = %d, want a retry after the 503", registers)
	}
}

func TestManagerRefreshesATokenThatWouldExpireMidConnection(t *testing.T) {
	p := newStubPlane(t)
	// A token this short must never be reused for a fresh connection.
	p.setTokenTTL(time.Second)
	m := newTestManager(t, p, 1)
	run(t, m)

	p.waitAccepted(t, 2)
	p.mu.Lock()
	first := p.conns[0]
	p.mu.Unlock()
	_ = first.Close()
	p.waitAccepted(t, 1)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, refreshes := p.counts(); refreshes > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the manager reused a nearly expired token instead of refreshing it")
}

// A refused refresh must not be terminal: the JWT outlives any outage shorter
// than its TTL, so a longer one would otherwise leave the connector holding an
// expired token it can never replace, and the process would exit for good.
func TestManagerReRegistersAfterARefusedRefresh(t *testing.T) {
	p := newStubPlane(t)
	p.setTokenTTL(time.Second)
	p.setRefreshStatus(http.StatusUnauthorized)
	m := newTestManager(t, p, 1)
	run(t, m)

	p.waitAccepted(t, 2)
	p.mu.Lock()
	first := p.conns[0]
	p.mu.Unlock()
	_ = first.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		registers, refreshes := p.counts()
		if refreshes > 0 && registers >= 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	registers, refreshes := p.counts()
	t.Errorf("registers=%d refreshes=%d, want a re-registration after the refused refresh",
		registers, refreshes)
}

func TestManagerReturnsCleanlyOnCancellation(t *testing.T) {
	p := newStubPlane(t)
	m := newTestManager(t, p, 1)
	cancel, result := run(t, m)

	p.waitAccepted(t, 2)
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Errorf("Run() error = %v, want nil on graceful shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after cancellation")
	}
}

func TestManagerReMintsAfterTheGatewayRejectsTheToken(t *testing.T) {
	p := newStubPlane(t)
	// The gateway rejects the first upgrade the way it would for a jti a peer
	// connection just superseded.
	p.rejectUpgrades(http.StatusUnauthorized)

	m := newTestManager(t, p, 1)
	run(t, m)

	// Both lanes must end up connected, which requires the rejected one to mint
	// a new token rather than give up.
	p.waitAccepted(t, 2)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if registers, refreshes := p.counts(); registers+refreshes >= 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	registers, refreshes := p.counts()
	t.Errorf("registers=%d refreshes=%d, want a re-mint after the 401", registers, refreshes)
}

func TestManagerCountsStreamsAndReconnects(t *testing.T) {
	p := newStubPlane(t)
	m := newTestManager(t, p, 1)
	collector := metrics.New(time.Unix(0, 0))
	m.Metrics = collector
	run(t, m)

	p.waitAccepted(t, 2)
	waitForMetric(t, collector, "zenfra_vcs_connector_tunnel_streams 2")
	waitForMetric(t, collector, "zenfra_vcs_connector_stream_connects_total 2")

	p.mu.Lock()
	first := p.conns[0]
	p.mu.Unlock()
	_ = first.Close()

	// The lane comes back, so the connect counter climbs while the gauge returns
	// to the full complement — that difference is the reconnect signal.
	p.waitAccepted(t, 1)
	waitForMetric(t, collector, "zenfra_vcs_connector_stream_connects_total 3")
	waitForMetric(t, collector, "zenfra_vcs_connector_tunnel_streams 2")
}

// waitForMetric polls the collector's exposition until it contains want.
func waitForMetric(t *testing.T, collector *metrics.Collector, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		rec := httptest.NewRecorder()
		collector.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
		body = rec.Body.String()
		if strings.Contains(body, want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in:\n%s", want, body)
}

func TestManagerWorksWithoutMetrics(t *testing.T) {
	p := newStubPlane(t)
	m := newTestManager(t, p, 1)
	m.Metrics = nil
	run(t, m)

	p.waitAccepted(t, 2)
}
