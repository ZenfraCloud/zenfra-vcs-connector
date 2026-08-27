// ABOUTME: Tests for one tunnel WebSocket connection — dial, pumps, and protocol discipline.
// ABOUTME: A gorilla-based stub gateway drives requests; the connector side must answer correctly.
package connect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// testLogger discards connector logs unless a test asserts on them.
func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// testConfig is a valid connector configuration for wiring tests.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load([]string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", "vcsc_abc.def",
		"--endpoint", "https://gitlab.internal",
		"--vendor", "gitlab",
		"--secret-file", "/etc/zenfra/token",
		"--all-projects",
		"--instance-key", "connector-0",
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	return cfg
}

// stubGateway is a minimal gateway-side WebSocket endpoint for driving a Conn.
type stubGateway struct {
	srv *httptest.Server

	mu       sync.Mutex
	handshak []*http.Request
	accepted chan *websocket.Conn
}

func newStubGateway(t *testing.T, tlsMode bool) *stubGateway {
	t.Helper()
	g := &stubGateway{accepted: make(chan *websocket.Conn, 8)}
	upgrader := websocket.Upgrader{EnableCompression: false}
	mux := http.NewServeMux()
	mux.HandleFunc(tunnelPath, func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.handshak = append(g.handshak, r)
		g.mu.Unlock()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		g.accepted <- conn
	})
	if tlsMode {
		g.srv = httptest.NewTLSServer(mux)
	} else {
		g.srv = httptest.NewServer(mux)
	}
	t.Cleanup(g.srv.Close)
	return g
}

// url returns the gateway base URL as the connector configures it (http/https).
func (g *stubGateway) url() string { return g.srv.URL }

// next waits for the next accepted connection.
func (g *stubGateway) next(t *testing.T) *websocket.Conn {
	t.Helper()
	select {
	case conn := <-g.accepted:
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	case <-time.After(3 * time.Second):
		t.Fatal("gateway never accepted a connection")
		return nil
	}
}

func (g *stubGateway) handshakes() []*http.Request {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]*http.Request(nil), g.handshak...)
}

// send writes one envelope to the connector.
func send(t *testing.T, conn *websocket.Conn, env *tunnel.Envelope) {
	t.Helper()
	data, err := tunnel.Encode(env)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}
}

// recv reads the next envelope from the connector.
func recv(t *testing.T, conn *websocket.Conn) *tunnel.Envelope {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	env, err := tunnel.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	return env
}

// testRequestID is the request ID the stub gateway uses for single-exchange tests.
const testRequestID = "r1"

func requestEnv(id string, hasBody bool) *tunnel.Envelope {
	return &tunnel.Envelope{
		RequestId: id,
		Msg: &tunnel.Envelope_HttpRequest{HttpRequest: &tunnel.HTTPRequest{
			Method:        http.MethodGet,
			Path:          "/api/v4/projects/42",
			DeadlineClass: tunnel.DeadlineClass_DEADLINE_CLASS_INTERACTIVE,
			HasBody:       hasBody,
		}},
	}
}

func chunkEnv(seq uint64, data []byte, terminal bool) *tunnel.Envelope {
	return &tunnel.Envelope{
		RequestId: testRequestID,
		Msg: &tunnel.Envelope_BodyChunk{BodyChunk: &tunnel.BodyChunk{
			Sequence: seq, Data: data, Terminal: terminal,
		}},
	}
}

// dialStub dials the stub gateway and serves the connection until the test ends.
func dialStub(t *testing.T, g *stubGateway, d *Dialer, lane Lane) (conn *Conn, served chan error) {
	t.Helper()
	if d.GatewayURL == "" {
		d.GatewayURL = g.url()
	}
	conn, err := d.Dial(context.Background(), "jwt-1", lane)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	served = make(chan error, 1)
	done := make(chan struct{})
	go func() {
		served <- conn.Serve(context.Background())
		close(done)
	}()
	t.Cleanup(func() {
		conn.Close()
		<-done
	})
	return conn, served
}

func testDialer(handler Handler) *Dialer {
	return &Dialer{
		Vendor:     "gitlab",
		Endpoint:   "https://gitlab.internal",
		PolicyHash: "sha256:policy",
		Handler:    handler,
		Config:     DefaultConnConfig(),
	}
}

func TestDialSendsTokenAndFingerprint(t *testing.T) {
	g := newStubGateway(t, false)
	d := testDialer(func(context.Context, *Request, *Responder) {})
	dialStub(t, g, d, LaneBulk)
	g.next(t)

	handshakes := g.handshakes()
	if len(handshakes) != 1 {
		t.Fatalf("handshakes = %d, want 1", len(handshakes))
	}
	r := handshakes[0]
	if got, want := r.Header.Get("Authorization"), "Bearer jwt-1"; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
	q := r.URL.Query()
	for _, tc := range []struct{ key, want string }{
		{"lane", string(LaneBulk)},
		{"vendor", "gitlab"},
		{"endpoint", "https://gitlab.internal"},
		{"policy_hash", "sha256:policy"},
	} {
		if got := q.Get(tc.key); got != tc.want {
			t.Errorf("query %s = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestDialRejectsNonHTTPGatewayURL(t *testing.T) {
	d := testDialer(nil)
	d.GatewayURL = "ftp://api.zenfra.cloud"
	if _, err := d.Dial(context.Background(), "jwt", LaneInteractive); err == nil {
		t.Fatal("Dial() error = nil, want error for a non-http gateway URL")
	}
}

func TestDialSurfacesHandshakeRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"policy_denied","message":"endpoint mismatch"}`))
	}))
	defer srv.Close()

	d := testDialer(nil)
	d.GatewayURL = srv.URL
	_, err := d.Dial(context.Background(), "jwt", LaneInteractive)
	if err == nil {
		t.Fatal("Dial() error = nil, want error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden {
		t.Fatalf("error = %v, want *APIError with status 403", err)
	}
	if IsRetryable(err) {
		t.Error("IsRetryable() = true, want false for a rejected fingerprint")
	}
}

func TestDialUsesCustomCABundle(t *testing.T) {
	g := newStubGateway(t, true)
	bundle := writeCABundle(t, g.srv.Certificate().Raw)

	t.Run("without the bundle the dial fails", func(t *testing.T) {
		d := testDialer(func(context.Context, *Request, *Responder) {})
		d.GatewayURL = g.url()
		if _, err := d.Dial(context.Background(), "jwt", LaneInteractive); err == nil {
			t.Fatal("Dial() error = nil, want a TLS verification failure")
		}
	})

	t.Run("with the bundle the dial succeeds", func(t *testing.T) {
		tlsCfg, err := TLSConfigFromCABundle(bundle)
		if err != nil {
			t.Fatalf("TLSConfigFromCABundle() error = %v", err)
		}
		if tlsCfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = %x, want TLS 1.2 floor", tlsCfg.MinVersion)
		}
		d := testDialer(func(context.Context, *Request, *Responder) {})
		d.GatewayURL = g.url()
		d.TLSConfig = tlsCfg
		dialStub(t, g, d, LaneInteractive)
		g.next(t)
	})
}

func TestTLSConfigFromCABundleRejectsBadInput(t *testing.T) {
	if _, err := TLSConfigFromCABundle(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("TLSConfigFromCABundle() error = nil for a missing file")
	}
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := TLSConfigFromCABundle(junk); err == nil {
		t.Error("TLSConfigFromCABundle() error = nil for a file with no certificates")
	}
}

func TestDialerDefaultsToEnvironmentProxy(t *testing.T) {
	d, err := NewDialer(testConfig(t), "sha256:policy", nil, nil)
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	if d.Proxy == nil {
		t.Fatal("Proxy = nil, want http.ProxyFromEnvironment so HTTPS_PROXY is honored")
	}
	if d.Vendor != "gitlab" || d.Endpoint != "https://gitlab.internal" {
		t.Errorf("dialer fingerprint = %q/%q, want the configured vendor and endpoint", d.Vendor, d.Endpoint)
	}
	// The default must read the environment rather than hard-code a route.
	req, _ := http.NewRequest(http.MethodGet, "https://api.zenfra.cloud", http.NoBody) //nolint:noctx // not sent
	if _, err := d.Proxy(req); err != nil {
		t.Errorf("Proxy() error = %v", err)
	}
}

func TestDialThroughHTTPProxy(t *testing.T) {
	g := newStubGateway(t, false)
	proxy, proxied := newStubProxy(t)

	d := testDialer(func(context.Context, *Request, *Responder) {})
	d.GatewayURL = g.url()
	d.Proxy = func(*http.Request) (*url.URL, error) { return proxy, nil }
	dialStub(t, g, d, LaneInteractive)
	g.next(t)

	select {
	case target := <-proxied:
		if !strings.Contains(target, g.srv.Listener.Addr().String()) {
			t.Errorf("proxy CONNECT target = %q, want the gateway address", target)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the dial did not go through the proxy")
	}
}

func TestConnRoundTripChunkedRequestAndResponse(t *testing.T) {
	g := newStubGateway(t, false)
	payload := bytes.Repeat([]byte("x"), 3*tunnel.DefaultChunkBytes+17)
	gotBody := make(chan []byte, 1)

	d := testDialer(func(_ context.Context, req *Request, w *Responder) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		gotBody <- body
		if err := w.Head(http.StatusOK, http.Header{"Content-Type": {"application/json"}}, true); err != nil {
			t.Errorf("Head() error = %v", err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Errorf("Write() error = %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	dialStub(t, g, d, LaneInteractive)
	conn := g.next(t)

	send(t, conn, requestEnv("r1", true))
	send(t, conn, chunkEnv(0, []byte("hello "), false))
	send(t, conn, chunkEnv(1, []byte("world"), true))

	select {
	case body := <-gotBody:
		if string(body) != "hello world" {
			t.Errorf("request body = %q, want %q", body, "hello world")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never received the request body")
	}

	head := recv(t, conn)
	if head.GetRequestId() != "r1" {
		t.Errorf("response request id = %q, want r1", head.GetRequestId())
	}
	respHead := head.GetHttpResponseHead()
	if respHead == nil {
		t.Fatalf("first response envelope = %v, want a response head", head)
	}
	if respHead.GetStatus() != http.StatusOK || !respHead.GetHasBody() {
		t.Errorf("head = %+v, want 200 with a body", respHead)
	}
	if got := respHead.GetHeaders()["Content-Type"].GetValues(); len(got) != 1 || got[0] != "application/json" {
		t.Errorf("Content-Type header = %v", got)
	}

	if assembled := readResponseBody(t, conn); !bytes.Equal(assembled, payload) {
		t.Errorf("response body = %d bytes, want %d", len(assembled), len(payload))
	}
}

// readResponseBody reads body chunks until the terminal one, checking sequencing
// and the size cap along the way.
func readResponseBody(t *testing.T, conn *websocket.Conn) []byte {
	t.Helper()
	var assembled []byte
	for wantSeq := uint64(0); ; wantSeq++ {
		env := recv(t, conn)
		chunk := env.GetBodyChunk()
		if chunk == nil {
			t.Fatalf("envelope = %v, want a body chunk", env)
		}
		if chunk.GetSequence() != wantSeq {
			t.Fatalf("chunk sequence = %d, want %d", chunk.GetSequence(), wantSeq)
		}
		if len(chunk.GetData()) > tunnel.MaxChunkBytes {
			t.Fatalf("chunk is %d bytes, over the %d cap", len(chunk.GetData()), tunnel.MaxChunkBytes)
		}
		assembled = append(assembled, chunk.GetData()...)
		if chunk.GetTerminal() {
			return assembled
		}
	}
}

func TestConnBodilessRequestAndResponse(t *testing.T) {
	g := newStubGateway(t, false)
	sawNilBody := make(chan bool, 1)

	d := testDialer(func(_ context.Context, req *Request, w *Responder) {
		sawNilBody <- req.Body == nil
		_ = w.Head(http.StatusNoContent, nil, false)
	})
	dialStub(t, g, d, LaneInteractive)
	conn := g.next(t)

	send(t, conn, requestEnv("r1", false))
	if body := <-sawNilBody; !body {
		t.Error("req.Body != nil for a bodiless request")
	}
	head := recv(t, conn).GetHttpResponseHead()
	if head.GetStatus() != http.StatusNoContent || head.GetHasBody() {
		t.Errorf("head = %+v, want 204 without a body", head)
	}
}

func TestConnHandlerErrorSurfacesTypedError(t *testing.T) {
	g := newStubGateway(t, false)
	d := testDialer(func(_ context.Context, _ *Request, w *Responder) {
		_ = w.Fail(tunnel.ErrCodePolicyDenied, "path not allowlisted", false,
			tunnel.ErrorOrigin_ERROR_ORIGIN_CONNECTOR)
	})
	dialStub(t, g, d, LaneInteractive)
	conn := g.next(t)

	send(t, conn, requestEnv("r1", false))
	e := recv(t, conn).GetError()
	if e == nil {
		t.Fatal("envelope carried no error")
	}
	if e.GetCode() != tunnel.ErrCodePolicyDenied || e.GetRetryable() ||
		e.GetOrigin() != tunnel.ErrorOrigin_ERROR_ORIGIN_CONNECTOR {
		t.Errorf("error = %+v", e)
	}
}

func TestConnCancelCancelsHandlerContext(t *testing.T) {
	g := newStubGateway(t, false)
	d := testDialer(func(ctx context.Context, _ *Request, w *Responder) {
		<-ctx.Done()
		_ = w.CancelAck(tunnel.CancelOutcome_CANCEL_OUTCOME_OUTCOME_UNKNOWN)
	})
	dialStub(t, g, d, LaneInteractive)
	conn := g.next(t)

	send(t, conn, requestEnv("r1", false))
	send(t, conn, &tunnel.Envelope{
		RequestId: "r1", Msg: &tunnel.Envelope_Cancel{Cancel: &tunnel.Cancel{}},
	})

	ack := recv(t, conn).GetCancelAck()
	if ack == nil {
		t.Fatal("envelope carried no cancel ack")
	}
	if ack.GetOutcome() != tunnel.CancelOutcome_CANCEL_OUTCOME_OUTCOME_UNKNOWN {
		t.Errorf("outcome = %v", ack.GetOutcome())
	}
}

func TestConnCancelOutsideAnExchange(t *testing.T) {
	tests := []struct {
		name       string
		runFirst   bool
		cancelID   string
		wantOutcom tunnel.CancelOutcome
	}{
		{
			name:       "unknown request was never sent",
			cancelID:   "never-seen",
			wantOutcom: tunnel.CancelOutcome_CANCEL_OUTCOME_NOT_SENT,
		},
		{
			name:       "settled request already completed",
			runFirst:   true,
			cancelID:   "r1",
			wantOutcom: tunnel.CancelOutcome_CANCEL_OUTCOME_COMPLETED,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newStubGateway(t, false)
			d := testDialer(func(_ context.Context, _ *Request, w *Responder) {
				_ = w.Head(http.StatusOK, nil, false)
			})
			dialStub(t, g, d, LaneInteractive)
			conn := g.next(t)

			if tt.runFirst {
				send(t, conn, requestEnv("r1", false))
				if head := recv(t, conn).GetHttpResponseHead(); head == nil {
					t.Fatal("expected a response head before cancelling")
				}
			}
			send(t, conn, &tunnel.Envelope{
				RequestId: tt.cancelID, Msg: &tunnel.Envelope_Cancel{Cancel: &tunnel.Cancel{}},
			})
			ack := recv(t, conn).GetCancelAck()
			if ack == nil {
				t.Fatal("envelope carried no cancel ack")
			}
			if ack.GetOutcome() != tt.wantOutcom {
				t.Errorf("outcome = %v, want %v", ack.GetOutcome(), tt.wantOutcom)
			}
		})
	}
}

func TestConnProtocolViolationsEndTheConnection(t *testing.T) {
	tests := []struct {
		name string
		// hold keeps the first request's handler running so the violation is
		// observed against a genuinely in-flight exchange.
		hold  bool
		drive func(t *testing.T, conn *websocket.Conn)
	}{
		{
			name: "second request while one is in flight",
			hold: true,
			drive: func(t *testing.T, conn *websocket.Conn) {
				send(t, conn, requestEnv("r1", false))
				send(t, conn, requestEnv("r2", false))
			},
		},
		{
			name: "request id reused after settling",
			drive: func(t *testing.T, conn *websocket.Conn) {
				send(t, conn, requestEnv("r1", false))
				if head := recv(t, conn).GetHttpResponseHead(); head == nil {
					t.Fatal("expected a response head")
				}
				send(t, conn, requestEnv("r1", false))
			},
		},
		{
			name: "chunk sequence gap",
			drive: func(t *testing.T, conn *websocket.Conn) {
				send(t, conn, requestEnv("r1", true))
				send(t, conn, chunkEnv(3, []byte("gap"), true))
			},
		},
		{
			name: "body chunk for a bodiless request",
			drive: func(t *testing.T, conn *websocket.Conn) {
				send(t, conn, requestEnv("r1", false))
				send(t, conn, chunkEnv(0, []byte("nope"), true))
			},
		},
		{
			name: "gateway-role response head",
			drive: func(t *testing.T, conn *websocket.Conn) {
				send(t, conn, &tunnel.Envelope{
					RequestId: "r1",
					Msg: &tunnel.Envelope_HttpResponseHead{
						HttpResponseHead: &tunnel.HTTPResponseHead{Status: 200},
					},
				})
			},
		},
		{
			name: "gateway-role cancel ack",
			drive: func(t *testing.T, conn *websocket.Conn) {
				send(t, conn, &tunnel.Envelope{
					RequestId: "r1",
					Msg:       &tunnel.Envelope_CancelAck{CancelAck: &tunnel.CancelAck{}},
				})
			},
		},
		{
			name: "undecodable frame",
			drive: func(t *testing.T, conn *websocket.Conn) {
				if err := conn.WriteMessage(websocket.BinaryMessage, []byte{0xff, 0xff, 0xff}); err != nil {
					t.Fatalf("WriteMessage() error = %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newStubGateway(t, false)
			release := make(chan struct{})
			defer close(release)
			// A body reader that is never drained must not wedge the read pump.
			d := testDialer(func(_ context.Context, _ *Request, w *Responder) {
				if tt.hold {
					<-release
					return
				}
				_ = w.Head(http.StatusOK, nil, false)
			})
			_, served := dialStub(t, g, d, LaneInteractive)
			conn := g.next(t)

			tt.drive(t, conn)

			select {
			case err := <-served:
				if err == nil {
					t.Error("Serve() error = nil, want a protocol violation error")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the connection stayed open after a protocol violation")
			}
		})
	}
}

func TestConnAnswersGatewayPings(t *testing.T) {
	g := newStubGateway(t, false)
	d := testDialer(func(context.Context, *Request, *Responder) {})
	dialStub(t, g, d, LaneInteractive)
	conn := g.next(t)

	pongs := make(chan struct{}, 1)
	conn.SetPongHandler(func(string) error {
		select {
		case pongs <- struct{}{}:
		default:
		}
		return nil
	})
	if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
		t.Fatalf("WriteControl() error = %v", err)
	}
	// A read is required for gorilla to process the pong control frame.
	go func() {
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _, _ = conn.ReadMessage()
	}()

	select {
	case <-pongs:
	case <-time.After(3 * time.Second):
		t.Fatal("the connector never answered the gateway ping")
	}
}

func TestConnReadDeadlineEndsASilentConnection(t *testing.T) {
	g := newStubGateway(t, false)
	d := testDialer(func(context.Context, *Request, *Responder) {})
	d.Config.PongWait = 150 * time.Millisecond
	_, served := dialStub(t, g, d, LaneInteractive)
	g.next(t) // accepted, then deliberately silent

	select {
	case err := <-served:
		if err == nil {
			t.Error("Serve() error = nil, want a read timeout")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the connector kept a silent connection open past its read deadline")
	}
}

func TestConnClosedConnectionCancelsTheHandler(t *testing.T) {
	g := newStubGateway(t, false)
	handlerDone := make(chan error, 1)
	d := testDialer(func(ctx context.Context, _ *Request, _ *Responder) {
		<-ctx.Done()
		handlerDone <- ctx.Err()
	})
	conn, _ := dialStub(t, g, d, LaneInteractive)
	gwConn := g.next(t)

	send(t, gwConn, requestEnv("r1", false))
	// Give the handler a moment to start before pulling the connection.
	time.Sleep(50 * time.Millisecond)
	conn.Close()

	select {
	case err := <-handlerDone:
		if err == nil {
			t.Error("handler context error = nil, want cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("closing the connection did not cancel the in-flight handler")
	}
}

func TestConnResponderRejectsOutOfOrderUse(t *testing.T) {
	g := newStubGateway(t, false)
	errs := make(chan []error, 1)
	d := testDialer(func(_ context.Context, _ *Request, w *Responder) {
		var got []error
		if _, err := w.Write([]byte("early")); err != nil {
			got = append(got, err)
		}
		_ = w.Head(http.StatusOK, nil, true)
		if err := w.Head(http.StatusOK, nil, true); err != nil {
			got = append(got, err)
		}
		_ = w.Close()
		if _, err := w.Write([]byte("late")); err != nil {
			got = append(got, err)
		}
		errs <- got
	})
	dialStub(t, g, d, LaneInteractive)
	conn := g.next(t)
	send(t, conn, requestEnv("r1", false))

	got := <-errs
	if len(got) != 3 {
		t.Fatalf("errors = %v, want a write-before-head, duplicate-head and write-after-close error", got)
	}
}

func TestConnBlockedWriterClosesTheConnection(t *testing.T) {
	blocked := newBlockingConn()
	defer close(blocked.release)

	cfg := DefaultConnConfig()
	cfg.OutboundQueue = 1
	cfg.WriteWait = 50 * time.Millisecond
	c := newConn(blocked, cfg, func(context.Context, *Request, *Responder) {}, testLogger())

	served := make(chan error, 1)
	go func() { served <- c.Serve(context.Background()) }()

	// The pump takes the first envelope and blocks inside WriteMessage; the queue
	// then fills and the next enqueue must time out and drop the connection.
	var lastErr error
	for range 8 {
		if lastErr = c.enqueue(&tunnel.Envelope{
			RequestId: "r1",
			Msg:       &tunnel.Envelope_CancelAck{CancelAck: &tunnel.CancelAck{}},
		}); lastErr != nil {
			break
		}
	}
	if lastErr == nil {
		t.Fatal("enqueue() error = nil, want a write timeout once the peer stops draining")
	}
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("a blocked writer did not close the connection")
	}
}

// blockingConn is a wsConn whose writes never complete until it is closed.
type blockingConn struct {
	release   chan struct{}
	closeOnce sync.Once
	closed    chan struct{}
}

func newBlockingConn() *blockingConn {
	return &blockingConn{release: make(chan struct{}), closed: make(chan struct{})}
}

func (b *blockingConn) wait() error {
	select {
	case <-b.release:
	case <-b.closed:
	}
	return errors.New("closed")
}

func (b *blockingConn) ReadMessage() (messageType int, data []byte, err error) {
	return 0, nil, b.wait()
}

func (b *blockingConn) WriteMessage(int, []byte) error            { return b.wait() }
func (b *blockingConn) WriteControl(int, []byte, time.Time) error { return nil }
func (b *blockingConn) SetReadDeadline(time.Time) error           { return nil }
func (b *blockingConn) SetWriteDeadline(time.Time) error          { return nil }
func (b *blockingConn) SetReadLimit(int64)                        {}
func (b *blockingConn) SetPingHandler(func(string) error)         {}

func (b *blockingConn) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}

// writeCABundle writes a DER certificate out as a PEM bundle file.
func writeCABundle(t *testing.T, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("writing CA bundle: %v", err)
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Fatalf("test certificate is not parseable: %v", err)
	}
	return path
}

// newStubProxy starts an HTTP CONNECT proxy and reports the targets it tunnels.
func newStubProxy(t *testing.T) (proxyURL *url.URL, targets chan string) {
	t.Helper()
	targets = make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		targets <- r.Host
		upstream, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", r.Host)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			_ = upstream.Close()
			return
		}
		client, buf, err := hijacker.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
		_ = buf.Flush()
		go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close() }()
		go func() { _, _ = io.Copy(client, upstream); _ = client.Close() }()
	}))
	t.Cleanup(srv.Close)
	proxyURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing proxy URL: %v", err)
	}
	return proxyURL, targets
}
