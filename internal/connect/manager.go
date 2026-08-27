// ABOUTME: Connection manager keeping N interactive plus one bulk tunnel stream connected.
// ABOUTME: Owns the register→JWT→dial lifecycle, capped jittered reconnect backoff and token refresh.
package connect

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
)

// Reconnect and token-lifecycle bounds.
const (
	// DefaultBackoffBase is the first reconnect delay.
	DefaultBackoffBase = time.Second
	// DefaultBackoffCap bounds the reconnect delay.
	DefaultBackoffCap = 30 * time.Second
	// DefaultRefreshSkew exceeds the gateway's connection lifetime cap (45m) so a
	// token can never expire mid-connection and strand the stream.
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
	return d/2 + time.Duration(rand.Float64()*float64(d/2)) //nolint:gosec // jitter, not crypto
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
			instanceKey:    cfg.InstanceKey,
			version:        version,
			skew:           DefaultRefreshSkew,
			now:            time.Now,
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
		established, err := m.connectOnce(ctx, lane)
		if ctx.Err() != nil {
			return nil
		}
		if !IsRetryable(err) {
			logger.Error("tunnel stream stopped permanently", "error", err)
			return err
		}
		if established {
			// The stream did real work before dropping; start the ladder over.
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
	instanceKey    string
	version        string
	skew           time.Duration
	now            func() time.Time

	mu  sync.Mutex
	cur *Instance
}

// get returns a token valid for a whole connection lifetime, registering or
// refreshing when the current one is missing or too close to expiry.
func (t *tokenSource) get(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.cur == nil {
		inst, err := t.client.Register(ctx, t.bootstrapToken, t.instanceKey, t.version)
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
	// need per-instance jti support (plan Task 20).
	inst, err := t.client.Refresh(ctx, t.cur.Token)
	if err != nil {
		return "", err
	}
	t.cur = inst
	return inst.Token, nil
}

// invalidate drops token if it is still the current one, forcing a re-mint.
func (t *tokenSource) invalidate(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur != nil && t.cur.Token == token {
		t.cur = nil
	}
}
