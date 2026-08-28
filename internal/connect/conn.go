// ABOUTME: One tunnel WebSocket connection to the gateway — dial, read pump, serialized write pump.
// ABOUTME: Carries a single exchange at a time and hands each request to a Handler goroutine.
package connect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// Lane selects which gateway lane a connection serves. The values are wire
// values in the tunnel upgrade query — they must match the gateway's lanes.
type Lane string

const (
	// LaneInteractive carries short control-plane calls.
	LaneInteractive Lane = "interactive"
	// LaneBulk carries archive downloads so they cannot starve interactive calls.
	LaneBulk Lane = "bulk"
)

// maxFrameBytes caps an inbound frame: one max-size chunk plus envelope overhead.
// It mirrors the gateway's own limit.
const maxFrameBytes = tunnel.MaxChunkBytes + 32*1024

// Connection bounds, see DefaultConnConfig.
const (
	// defaultPongWait must exceed the gateway's ping interval (30s) by enough to
	// tolerate two missed pings.
	defaultPongWait  = 70 * time.Second
	defaultWriteWait = 10 * time.Second
	// defaultBulkWriteWait governs the bulk lane. The gateway tolerates a 60s gap
	// between response body chunks, so a shorter wait here would kill an archive
	// download the gateway was still willing to wait for.
	defaultBulkWriteWait    = 90 * time.Second
	defaultHandshakeTimeout = 15 * time.Second
	defaultOutboundQueue    = 8
)

// ErrProtocol marks a frame the connector must not accept; it always ends the
// connection.
var ErrProtocol = errors.New("tunnel protocol violation")

// errSuperseded fails an exchange the gateway walked away from.
var errSuperseded = errors.New("connect: exchange superseded by the next request")

// ConnConfig bounds one tunnel connection.
type ConnConfig struct {
	// PongWait bounds a single blocking read. The gateway drives keepalive, so a
	// gateway that neither pings nor sends frames within it is declared gone.
	PongWait time.Duration
	// WriteWait bounds one frame write and the wait for outbound queue space.
	WriteWait time.Duration
	// BulkWriteWait replaces WriteWait on the bulk lane, where a stalled consumer
	// downstream of the gateway is normal backpressure rather than a dead peer.
	BulkWriteWait time.Duration
	// HandshakeTimeout bounds the WebSocket upgrade.
	HandshakeTimeout time.Duration
	// OutboundQueue is the depth of the per-connection write queue.
	OutboundQueue int
}

// DefaultConnConfig returns the Phase 1 connection bounds.
func DefaultConnConfig() ConnConfig {
	return ConnConfig{
		PongWait:         defaultPongWait,
		WriteWait:        defaultWriteWait,
		BulkWriteWait:    defaultBulkWriteWait,
		HandshakeTimeout: defaultHandshakeTimeout,
		OutboundQueue:    defaultOutboundQueue,
	}
}

// Request is one inbound tunneled request.
type Request struct {
	// ID is the gateway-assigned request ID; every response envelope repeats it.
	ID   string
	Head *tunnel.HTTPRequest
	// Body streams the request body, or is nil when the request carries none.
	Body io.Reader
}

// Handler serves one tunneled request. ctx is cancelled when the gateway cancels
// the request or the connection drops. The policy engine and upstream executor
// supply the real implementation.
type Handler func(ctx context.Context, req *Request, w *Responder)

// wsConn is the subset of *websocket.Conn the pumps use.
type wsConn interface {
	ReadMessage() (int, []byte, error)
	WriteMessage(messageType int, data []byte) error
	WriteControl(messageType int, data []byte, deadline time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SetReadLimit(limit int64)
	SetPingHandler(h func(appData string) error)
	Close() error
}

// Dialer opens tunnel connections for one connector instance.
type Dialer struct {
	// GatewayURL is the zenfra-api base URL; ws/wss is derived from its scheme.
	GatewayURL string
	// Vendor, Endpoint and PolicyHash form the fingerprint the gateway checks
	// before upgrading.
	Vendor     string
	Endpoint   string
	PolicyHash string
	// TLSConfig pins trust roots for the gateway leg; nil uses system roots.
	TLSConfig *tls.Config
	// Proxy resolves an outbound proxy, defaulting to http.ProxyFromEnvironment.
	Proxy   func(*http.Request) (*url.URL, error)
	Config  ConnConfig
	Handler Handler
	Logger  *slog.Logger
}

// NewDialer builds a dialer from the connector configuration. policyHash is the
// fingerprint of the compiled allowlist this instance enforces.
func NewDialer(cfg *config.Config, policyHash string, handler Handler, logger *slog.Logger) (*Dialer, error) {
	d := &Dialer{
		GatewayURL: cfg.GatewayURL,
		Vendor:     string(cfg.Vendor),
		Endpoint:   cfg.Endpoint,
		PolicyHash: policyHash,
		Proxy:      http.ProxyFromEnvironment,
		Config:     DefaultConnConfig(),
		Handler:    handler,
		Logger:     logger,
	}
	if cfg.CABundle != "" {
		tlsCfg, err := TLSConfigFromCABundle(cfg.CABundle)
		if err != nil {
			return nil, err
		}
		d.TLSConfig = tlsCfg
	} else {
		d.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return d, nil
}

// TLSConfigFromCABundle builds a TLS config trusting only the PEM bundle at path.
// Corporate deployments terminate the gateway leg on an internal CA.
func TLSConfigFromCABundle(path string) (*tls.Config, error) {
	pemBytes, err := os.ReadFile(path) //nolint:gosec // the operator chooses the bundle path
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("CA bundle %s contains no certificates", path)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// tunnelURL builds the WebSocket URL for one lane.
func (d *Dialer) tunnelURL(lane Lane) (string, error) {
	base, err := url.Parse(d.GatewayURL)
	if err != nil {
		return "", fmt.Errorf("parsing gateway URL: %w", err)
	}
	switch base.Scheme {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	default:
		return "", fmt.Errorf("gateway URL scheme must be http or https, got %q", base.Scheme)
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + tunnelPath
	base.RawQuery = url.Values{
		"lane":        {string(lane)},
		"vendor":      {d.Vendor},
		"endpoint":    {d.Endpoint},
		"policy_hash": {d.PolicyHash},
	}.Encode()
	return base.String(), nil
}

// Dial opens one tunnel connection. The caller must run Serve to drive it.
func (d *Dialer) Dial(ctx context.Context, token string, lane Lane) (*Conn, error) {
	target, err := d.tunnelURL(lane)
	if err != nil {
		return nil, err
	}
	dialer := &websocket.Dialer{
		Proxy:             d.Proxy,
		TLSClientConfig:   d.TLSConfig,
		HandshakeTimeout:  d.Config.HandshakeTimeout,
		EnableCompression: false,
		ReadBufferSize:    tunnel.DefaultChunkBytes,
		WriteBufferSize:   tunnel.DefaultChunkBytes,
	}

	conn, resp, err := dialer.DialContext(ctx, target, http.Header{
		"Authorization": {"Bearer " + token},
	})
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		if resp != nil {
			// The gateway rejected the fingerprint or the token: report why, and
			// whether retrying could help.
			return nil, decodeAPIError(resp)
		}
		return nil, fmt.Errorf("dialing tunnel %s lane: %w", lane, err)
	}

	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	cfg := d.Config
	if lane == LaneBulk && cfg.BulkWriteWait > 0 {
		cfg.WriteWait = cfg.BulkWriteWait
	}
	return newConn(conn, cfg, d.Handler, logger.With("lane", string(lane))), nil
}

// Conn is one tunnel connection. It carries a single exchange at a time, matching
// the gateway's one-request-per-stream lease.
type Conn struct {
	conn    wsConn
	cfg     ConnConfig
	handler Handler
	logger  *slog.Logger

	out       chan []byte
	closed    chan struct{}
	closeOnce sync.Once

	// eventsMu guards the acks owed to in-flight connector-originated events.
	// Separate from mu: events run alongside the single request exchange, not
	// inside it.
	eventsMu sync.Mutex
	events   map[string]chan *tunnel.EventAck
	eventSeq atomic.Uint64

	mu sync.Mutex
	// current is the in-flight exchange, nil between requests.
	current *inflight
	// lastID is the most recently settled request ID, so a cancel arriving after
	// completion can be answered truthfully.
	lastID string
}

// inflight is the connector-side state of one exchange.
type inflight struct {
	requestID string
	cancel    context.CancelFunc

	// body and chunks are nil when the request carries no body.
	body    *io.PipeWriter
	chunks  *tunnel.ChunkSequencer
	discard bool
}

func newConn(conn wsConn, cfg ConnConfig, handler Handler, logger *slog.Logger) *Conn {
	return &Conn{
		conn:    conn,
		cfg:     cfg,
		handler: handler,
		logger:  logger,
		out:     make(chan []byte, cfg.OutboundQueue),
		closed:  make(chan struct{}),
	}
}

// Close terminates the connection and cancels any in-flight handler.
func (c *Conn) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
		c.mu.Lock()
		ex := c.current
		c.mu.Unlock()
		if ex != nil {
			ex.abort(errors.New("connect: connection closed"))
		}
	})
}

// Serve runs the read pump until the connection ends, with the write pump
// alongside it. It returns the error that ended the connection.
func (c *Conn) Serve(ctx context.Context) error {
	defer c.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.writePump()
	go func() {
		// A cancelled caller context must tear the connection down too.
		select {
		case <-ctx.Done():
			c.Close()
		case <-c.closed:
		}
	}()

	c.conn.SetReadLimit(maxFrameBytes)
	c.conn.SetPingHandler(func(data string) error {
		if err := c.conn.SetReadDeadline(time.Now().Add(c.cfg.PongWait)); err != nil {
			return err
		}
		return c.conn.WriteControl(
			websocket.PongMessage, []byte(data), time.Now().Add(c.cfg.WriteWait),
		)
	})

	for {
		if err := c.conn.SetReadDeadline(time.Now().Add(c.cfg.PongWait)); err != nil {
			return fmt.Errorf("setting read deadline: %w", err)
		}
		msgType, data, err := c.conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("tunnel read: %w", err)
		}
		if msgType != websocket.BinaryMessage {
			continue
		}
		env, decErr := tunnel.Decode(data)
		if decErr != nil {
			return fmt.Errorf("%w: %w", ErrProtocol, decErr)
		}
		if err := c.dispatch(ctx, env); err != nil {
			return err
		}
	}
}

// dispatch routes one inbound envelope. A returned error ends the connection.
func (c *Conn) dispatch(ctx context.Context, env *tunnel.Envelope) error {
	// The gateway never sends responses, acks or events; a connector that
	// accepted them would be talking to something other than the gateway.
	if env.GetHttpResponseHead() != nil || env.GetCancelAck() != nil ||
		env.GetError() != nil || env.GetEvent() != nil {
		return fmt.Errorf("%w: gateway sent a connector-role message", ErrProtocol)
	}
	switch {
	case env.GetHttpRequest() != nil:
		return c.startExchange(ctx, env)
	case env.GetBodyChunk() != nil:
		return c.deliverChunk(env)
	case env.GetCancel() != nil:
		return c.deliverCancel(env.GetRequestId())
	case env.GetEventAck() != nil:
		return c.deliverEventAck(env)
	}
	return fmt.Errorf("%w: envelope carried no known message", ErrProtocol)
}

// startExchange begins one request and hands it to the handler goroutine.
func (c *Conn) startExchange(ctx context.Context, env *tunnel.Envelope) error {
	head := env.GetHttpRequest()
	requestID := env.GetRequestId()

	c.mu.Lock()
	// The gateway carries one exchange at a time per stream, so a second request
	// can only mean it stopped waiting for the previous one: the caller closed the
	// response body early, the body idle timeout fired, or a cancel went
	// unacknowledged. Supersede the stale exchange instead of failing the
	// connection, which would take every other in-flight request with it.
	stale := c.current
	// Checked before the supersede below mutates anything: on this error path the
	// stale exchange stays c.current, so Close aborts its body pipe and its
	// handler goroutine settles. Detaching it first would strand both for the
	// process's lifetime.
	if requestID == c.lastID || (stale != nil && stale.requestID == requestID) {
		c.mu.Unlock()
		return fmt.Errorf("%w: %w: %q", ErrProtocol, tunnel.ErrDuplicateRequestID, requestID)
	}
	if stale != nil {
		c.current = nil
		c.lastID = stale.requestID
	}

	exCtx, cancel := context.WithCancel(ctx)
	ex := &inflight{requestID: requestID, cancel: cancel}
	var body io.Reader
	if head.GetHasBody() {
		reader, writer := io.Pipe()
		ex.body, ex.chunks, body = writer, tunnel.NewChunkSequencer(requestID), reader
	}
	c.current = ex
	c.mu.Unlock()

	if stale != nil {
		c.logger.Warn("superseding an abandoned request",
			"request_id", stale.requestID, "next_request_id", requestID)
		stale.cancel()
		stale.abort(errSuperseded)
	}

	resp := &Responder{conn: c, requestID: requestID}
	go func() {
		defer cancel()
		defer c.settle(ex)
		// A handler panic would otherwise kill the process with status 2 — the
		// code that tells an orchestrator "misconfigured, do not restart" — and
		// take every other lane's stream with it. One request fails instead.
		defer func() {
			if r := recover(); r != nil {
				c.logger.Error("panic handling tunneled request",
					"request_id", requestID, "panic", fmt.Sprint(r))
				// ErrCodeProtocol is the gateway's catch-all: an unknown code is
				// normalized to it anyway, so a new one would buy nothing.
				_ = resp.Fail(tunnel.ErrCodeProtocol, "connector failed to handle the request",
					false, tunnel.ErrorOrigin_ERROR_ORIGIN_CONNECTOR)
			}
		}()
		c.handler(exCtx, &Request{ID: requestID, Head: head, Body: body}, resp)
	}()
	return nil
}

// deliverChunk validates one request body chunk and writes it to the body pipe.
// The write blocks until the handler reads, which is the tunnel's backpressure.
func (c *Conn) deliverChunk(env *tunnel.Envelope) error {
	c.mu.Lock()
	ex := c.current
	if ex == nil || ex.requestID != env.GetRequestId() {
		settled := env.GetRequestId() == c.lastID
		c.mu.Unlock()
		if settled {
			// The handler already answered without draining the body — a policy
			// denial refuses before reading it. The gateway streams the head and
			// its chunks back to back, so the rest arrives after the refusal;
			// dropping it keeps the connection, as the gateway does in reverse.
			return nil
		}
		return fmt.Errorf("%w: body chunk for %q outside its exchange", ErrProtocol, env.GetRequestId())
	}
	if ex.chunks == nil {
		c.mu.Unlock()
		return fmt.Errorf("%w: body chunk for bodiless request %q", ErrProtocol, ex.requestID)
	}
	if err := ex.chunks.Accept(env); err != nil {
		c.mu.Unlock()
		ex.abort(err)
		return fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	body, discard := ex.body, ex.discard
	c.mu.Unlock()

	chunk := env.GetBodyChunk()
	if discard {
		return nil
	}
	if _, err := body.Write(chunk.GetData()); err != nil {
		// The handler stopped reading; drop the rest of this body but keep the
		// connection, since the handler still owes a response.
		c.markDiscard(ex)
		return nil
	}
	if chunk.GetTerminal() {
		_ = body.Close()
	}
	return nil
}

// deliverCancel cancels the in-flight handler, or answers directly when the
// exchange is already gone.
func (c *Conn) deliverCancel(requestID string) error {
	c.mu.Lock()
	ex, lastID := c.current, c.lastID
	c.mu.Unlock()

	if ex != nil && ex.requestID == requestID {
		// The handler owns the ack: only it knows whether the upstream call landed.
		// Fail the body pipe too — the handler buffers the request body with a
		// plain read that no context cancels, so without this a cancel arriving
		// mid-body would wedge the exchange until the connection lifetime expires.
		ex.cancel()
		ex.abort(context.Canceled)
		return nil
	}
	outcome := tunnel.CancelOutcome_CANCEL_OUTCOME_NOT_SENT
	if requestID == lastID {
		outcome = tunnel.CancelOutcome_CANCEL_OUTCOME_COMPLETED
	}
	return c.enqueue(&tunnel.Envelope{
		RequestId: requestID,
		Msg:       &tunnel.Envelope_CancelAck{CancelAck: &tunnel.CancelAck{Outcome: outcome}},
	})
}

// settle frees the connection for the next request.
func (c *Conn) settle(ex *inflight) {
	// Defensive: an undrained body would otherwise wedge the read pump.
	ex.abort(errors.New("connect: exchange settled"))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == ex {
		c.current = nil
		c.lastID = ex.requestID
	}
}

func (c *Conn) markDiscard(ex *inflight) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ex.discard = true
}

// abort fails the body pipe so a blocked read pump or handler is released.
func (ex *inflight) abort(err error) {
	if ex.body != nil {
		_ = ex.body.CloseWithError(err)
	}
}

// enqueue hands one envelope to the write pump, bounded by WriteWait.
func (c *Conn) enqueue(env *tunnel.Envelope) error {
	data, err := tunnel.Encode(env)
	if err != nil {
		return fmt.Errorf("encoding tunnel envelope: %w", err)
	}
	// Checked first and on its own: c.out keeps buffer capacity after Close, so a
	// combined select would pick it at random and report a frame as sent that no
	// write pump will ever drain.
	select {
	case <-c.closed:
		return errors.New("connect: connection closed")
	default:
	}

	timer := time.NewTimer(c.cfg.WriteWait)
	defer timer.Stop()

	select {
	case c.out <- data:
		return nil
	case <-c.closed:
		return errors.New("connect: connection closed")
	case <-timer.C:
		// The gateway stopped draining our writes: drop the connection rather
		// than pin memory on a peer that is not reading.
		c.logger.Warn("tunnel writer blocked, closing connection")
		c.Close()
		return errors.New("connect: tunnel write timed out")
	}
}

// writePump is the only writer of data frames on the connection.
func (c *Conn) writePump() {
	for {
		select {
		case data := <-c.out:
			if err := c.conn.SetWriteDeadline(time.Now().Add(c.cfg.WriteWait)); err != nil {
				c.Close()
				return
			}
			if err := c.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
				c.Close()
				return
			}
		case <-c.closed:
			return
		}
	}
}

// Responder writes the response for one exchange. It is used by a single handler
// goroutine and is not safe for concurrent use.
type Responder struct {
	conn      *Conn
	requestID string

	seq      uint64
	headSent bool
	bodyDone bool
}

// Head sends the response status and headers. hasBody must be true when body
// chunks follow; the exchange then ends with Close.
func (r *Responder) Head(status int, header http.Header, hasBody bool) error {
	if r.headSent {
		return errors.New("connect: response head already sent")
	}
	r.headSent = true
	r.bodyDone = !hasBody
	return r.conn.enqueue(&tunnel.Envelope{
		RequestId: r.requestID,
		Msg: &tunnel.Envelope_HttpResponseHead{HttpResponseHead: &tunnel.HTTPResponseHead{
			Status:  int32(status), //nolint:gosec // HTTP status codes fit in int32
			Headers: headersToProto(header),
			HasBody: hasBody,
		}},
	})
}

// Write streams response body bytes, splitting them into protocol-sized chunks.
func (r *Responder) Write(p []byte) (int, error) {
	if !r.headSent {
		return 0, errors.New("connect: response body written before the head")
	}
	if r.bodyDone {
		return 0, errors.New("connect: response body already closed")
	}
	for written := 0; written < len(p); {
		end := min(written+tunnel.DefaultChunkBytes, len(p))
		if err := r.chunk(p[written:end], false); err != nil {
			return written, err
		}
		written = end
	}
	return len(p), nil
}

// Close sends the terminal chunk, ending the response body.
func (r *Responder) Close() error {
	if !r.headSent {
		return errors.New("connect: response closed before the head")
	}
	if r.bodyDone {
		return nil
	}
	r.bodyDone = true
	return r.chunk(nil, true)
}

func (r *Responder) chunk(data []byte, terminal bool) error {
	env := &tunnel.Envelope{
		RequestId: r.requestID,
		Msg: &tunnel.Envelope_BodyChunk{BodyChunk: &tunnel.BodyChunk{
			Sequence: r.seq, Data: data, Terminal: terminal,
		}},
	}
	r.seq++
	return r.conn.enqueue(env)
}

// Fail ends the exchange with a typed protocol error instead of a response.
func (r *Responder) Fail(code, message string, retryable bool, origin tunnel.ErrorOrigin) error {
	return r.conn.enqueue(&tunnel.Envelope{
		RequestId: r.requestID,
		Msg: &tunnel.Envelope_Error{Error: &tunnel.Error{
			Code: code, Message: message, Retryable: retryable, Origin: origin,
		}},
	})
}

// CancelAck reports the true terminal state of a cancelled request.
func (r *Responder) CancelAck(outcome tunnel.CancelOutcome) error {
	return r.conn.enqueue(&tunnel.Envelope{
		RequestId: r.requestID,
		Msg:       &tunnel.Envelope_CancelAck{CancelAck: &tunnel.CancelAck{Outcome: outcome}},
	})
}

func headersToProto(h http.Header) map[string]*tunnel.HeaderValues {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]*tunnel.HeaderValues, len(h))
	for name, values := range h {
		out[name] = &tunnel.HeaderValues{Values: values}
	}
	return out
}
