// ABOUTME: Connection manager keeping N interactive plus one bulk tunnel stream connected.
// ABOUTME: Owns the register→JWT→dial lifecycle, capped jittered reconnect backoff and token refresh.
package connect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/metrics"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// Reconnect and token-lifecycle bounds.
const (
	// DefaultBackoffBase is the first reconnect delay.
	DefaultBackoffBase = time.Second
	// DefaultBackoffCap bounds the reconnect delay.
	DefaultBackoffCap = 30 * time.Second
	// minUptimeForBackoffReset is how long a connection must last to count as
	// real work. Dial returning nil only means the 101 completed: an intermediary
	// that upgrades and immediately resets would otherwise hold the ladder at its
	// first rung forever, reconnecting sub-second without ever escalating.
	minUptimeForBackoffReset = 30 * time.Second
	// DefaultRefreshSkew exceeds the gateway's connection lifetime cap (45m) so a
	// token can never expire mid-connection and strand the stream.
	// service.VCSConnectorTokenTTL is sized so TTL-skew also exceeds that cap:
	// refreshing revokes the jti every stream shares, so a skew that fires on
	// every reconnect would turn one lane dropping into a fleet-wide restart.
	DefaultRefreshSkew = 50 * time.Minute
)

// Backoff returns the delay before retry attempt (0-based), jittered within
// [d/2, d] where d is base doubled per attempt and capped at maxDelay. The jitter
// keeps a fleet of instances from reconnecting in lockstep.
func Backoff(attempt int, base, maxDelay time.Duration) time.Duration {
	d := maxDelay
	if attempt >= 0 && attempt < 62 {
		if scaled := base << uint(attempt); scaled > 0 && scaled < maxDelay {
			d = scaled
		}
	}
	return d/2 + time.Duration(rand.Float64()*float64(d/2)) // #nosec G404 -- non-cryptographic reconnect jitter
}

// Manager keeps this instance's tunnel streams connected.
type Manager struct {
	client *Client
	dialer *Dialer
	tokens *tokenSource
	logger *slog.Logger

	interactive int

	// Reconnect bounds, overridable in tests.
	BackoffBase time.Duration
	BackoffCap  time.Duration

	// Metrics is the optional Prometheus collector; nil disables it.
	Metrics *metrics.Collector

	// mu guards live, the interactive connections an event may ride out on.
	mu   sync.Mutex
	live []*Conn
}

// SendEvent relays one event to the gateway over any live interactive
// connection. ponytail: first live connection wins — events are rare next to
// requests, so spreading them across streams would buy nothing.
func (m *Manager) SendEvent(ctx context.Context, event *tunnel.Event) (*tunnel.EventAck, error) {
	m.mu.Lock()
	var conn *Conn
	if len(m.live) > 0 {
		conn = m.live[0]
	}
	m.mu.Unlock()
	if conn == nil {
		return nil, ErrNoTunnel
	}
	return conn.SendEvent(ctx, event)
}

// track registers a live interactive connection for the event relay and returns
// its removal.
func (m *Manager) track(conn *Conn) func() {
	m.mu.Lock()
	m.live = append(m.live, conn)
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		for i, candidate := range m.live {
			if candidate == conn {
				m.live = append(m.live[:i], m.live[i+1:]...)
				return
			}
		}
	}
}

// NewManager wires a manager for one connector instance.
func NewManager(cfg *config.Config, client *Client, dialer *Dialer, version string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		client:      client,
		dialer:      dialer,
		logger:      logger,
		interactive: cfg.InteractiveConnections,
		BackoffBase: DefaultBackoffBase,
		BackoffCap:  DefaultBackoffCap,
		tokens: &tokenSource{
			client:         client,
			bootstrapToken: cfg.BootstrapToken,
			enrollment:     enrollmentStore{path: cfg.EnrollmentKeyFile},
			instanceKey:    cfg.InstanceKey,
			version:        version,
			skew:           DefaultRefreshSkew,
			now:            time.Now,
			logger:         logger,
		},
	}
}

// Run maintains every stream until ctx is cancelled. It returns nil on graceful
// shutdown, or the terminal error that made continuing pointless.
func (m *Manager) Run(ctx context.Context) error {
	lanes := make([]Lane, 0, m.interactive+1)
	for range m.interactive {
		lanes = append(lanes, LaneInteractive)
	}
	lanes = append(lanes, LaneBulk)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	fatal := make(chan error, len(lanes))
	var wg sync.WaitGroup
	for i, lane := range lanes {
		wg.Add(1)
		go func(lane Lane, index int) {
			defer wg.Done()
			if err := m.supervise(runCtx, lane, index); err != nil {
				fatal <- err
				// One unrecoverable stream means the whole connector is broken.
				cancel()
			}
		}(lane, i)
	}
	wg.Wait()

	if ctx.Err() != nil {
		return nil
	}
	select {
	case err := <-fatal:
		return err
	default:
		return nil
	}
}

// supervise keeps one lane connected, reconnecting with capped jittered backoff.
func (m *Manager) supervise(ctx context.Context, lane Lane, index int) error {
	logger := m.logger.With("lane", string(lane), "stream", index)

	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return nil
		}
		start := time.Now()
		established, err := m.connectOnce(ctx, lane)
		if ctx.Err() != nil {
			return nil
		}
		if !IsRetryable(err) {
			logger.Error("tunnel stream stopped permanently", "error", err)
			return err
		}
		if established && time.Since(start) >= minUptimeForBackoffReset {
			// The stream stayed up long enough to have done real work; start the
			// ladder over. An accept-then-drop loop keeps escalating instead.
			attempt = 0
		}
		delay := Backoff(attempt, m.BackoffBase, m.BackoffCap)
		logger.Warn("tunnel stream lost, reconnecting", "error", err, "delay", delay)

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// connectOnce mints a token, dials one stream and serves it until it ends. The
// bool reports whether the connection was established, which resets the backoff.
func (m *Manager) connectOnce(ctx context.Context, lane Lane) (bool, error) {
	token, err := m.tokens.get(ctx)
	if err != nil {
		return false, err
	}

	conn, err := m.dialer.Dial(ctx, token, lane)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			// A peer stream's refresh supersedes the shared jti, so an
			// unauthorized upgrade means re-mint rather than give up.
			m.tokens.invalidate(token)
			return false, &retryableError{err}
		}
		return false, err
	}

	m.Metrics.StreamOpened()
	defer m.Metrics.StreamClosed()
	if lane == LaneInteractive {
		// Events ride the interactive lane; the bulk lane is reserved for
		// archive transfers that would sit in front of them.
		defer m.track(conn)()
	}
	return true, conn.Serve(ctx)
}

// retryableError forces IsRetryable to true for a wrapped terminal-looking error.
type retryableError struct{ err error }

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

// Retryable satisfies the classification IsRetryable performs on *APIError.
func (e *retryableError) Retryable() bool { return true }

// tokenSource holds the instance's current JWT, minting or refreshing on demand.
// One instance record holds exactly one live jti, so every stream shares it.
type tokenSource struct {
	client         *Client
	bootstrapToken string
	// enrollment persists this instance's own key. Once stored it is what
	// registration presents, so revoking this instance ends its access for good —
	// the bootstrap token cannot bring it back.
	enrollment  enrollmentStore
	instanceKey string
	version     string
	skew        time.Duration
	now         func() time.Time
	logger      *slog.Logger

	mu  sync.Mutex
	cur *Instance
}

// get returns a token valid for a whole connection lifetime, registering or
// refreshing when the current one is missing or too close to expiry.
func (t *tokenSource) get(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.cur == nil {
		inst, err := t.register(ctx)
		if err != nil {
			return "", err
		}
		t.cur = inst
		return inst.Token, nil
	}
	if t.now().Add(t.skew).Before(t.cur.ExpiresAt) {
		return t.cur.Token, nil
	}

	// ponytail: refreshing revokes the jti every live stream shares, so the
	// gateway drops them and they reconnect on the new token. Per-stream tokens
	// would need one jti per stream; add that if the reconnect storm ever matters.
	inst, err := t.client.Refresh(ctx, t.cur.Token)
	if err != nil {
		// Drop the token and keep the lane retryable: the next attempt
		// re-registers with the enrollment key instead of replaying a token the
		// control plane just refused, which would otherwise end the process for
		// good once the JWT outlived any outage longer than the skew window.
		t.cur = nil
		return "", &retryableError{err}
	}
	t.cur = inst
	return inst.Token, nil
}

// codeInstanceUnknown is the control plane's answer to an enrollment key whose
// instance record was reclaimed (30 days without contact). Not a revocation: a
// revoked instance keeps its tombstone and answers 403 instance_revoked.
const codeInstanceUnknown = "instance_unknown"

// register presents the stored enrollment key when there is one, and the
// bootstrap token otherwise, persisting whatever key the response hands back. A
// refused enrollment key is never retried with the bootstrap token — that is the
// revocation this whole mechanism exists to make stick — with one exception: a
// key the control plane no longer recognises at all, which is a reclaimed
// record, not a revoked one.
func (t *tokenSource) register(ctx context.Context) (*Instance, error) {
	credential, err := t.enrollment.load()
	if err != nil {
		// Not a fallback to the bootstrap token: an unreadable key file must not
		// look like a host that never enrolled.
		return nil, err
	}
	enrolled := credential != ""
	if !enrolled {
		credential = t.bootstrapToken
	}

	inst, err := t.client.Register(ctx, credential, t.instanceKey, t.version)
	if err != nil && enrolled && isInstanceUnknown(err) {
		if t.bootstrapToken == "" {
			return nil, fmt.Errorf("%w: the stored enrollment key names an instance the control "+
				"plane no longer knows (its record is reclaimed after 30 days offline); start the "+
				"connector with the bootstrap token to enrol again", err)
		}
		t.logger.Warn("stored enrollment key names an instance the control plane no longer knows; "+
			"re-enrolling with the bootstrap token", "error", err)
		inst, err = t.client.Register(ctx, t.bootstrapToken, t.instanceKey, t.version)
	}
	if err != nil {
		if enrolled {
			t.logger.Error("registration with the stored enrollment key was refused; "+
				"remove the key file to enroll this instance again", "error", err)
		}
		return nil, err
	}

	if saveErr := t.enrollment.save(inst.EnrollmentKey); saveErr != nil {
		// The token works, so keep running; the cost is bootstrapping again on
		// the next restart rather than a failed connector.
		t.logger.Warn("could not persist the enrollment key", "error", saveErr)
	}
	return inst, nil
}

// isInstanceUnknown reports the one refusal register may answer with the
// bootstrap token.
func isInstanceUnknown(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) &&
		apiErr.Status == http.StatusUnauthorized && apiErr.Code == codeInstanceUnknown
}

// invalidate drops token if it is still the current one, forcing a re-mint.
func (t *tokenSource) invalidate(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur != nil && t.cur.Token == token {
		t.cur = nil
	}
}
