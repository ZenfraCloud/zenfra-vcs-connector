// ABOUTME: Tests for the upstream executor — credential injection, header discipline, streaming.
// ABOUTME: An httptest GitLab stub stands in for the customer's VCS; a fake responder records the reply.
package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/connect"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/policy"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// testSecret is the upstream credential; no test output may ever contain it.
const testSecret = "glpat-SUPERSECRET-do-not-log" //nolint:gosec // fake credential for tests

// fakeResponder records what the executor sent back through the tunnel.
type fakeResponder struct {
	mu       sync.Mutex
	headSent bool
	status   int
	header   http.Header
	hasBody  bool
	writes   []int
	body     bytes.Buffer
	closed   bool
	failure  *tunnel.Error
	ack      *tunnel.CancelAck

	headCh chan struct{}
}

func newFakeResponder() *fakeResponder {
	return &fakeResponder{headCh: make(chan struct{})}
}

func (f *fakeResponder) Head(status int, header http.Header, hasBody bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headSent, f.status, f.header, f.hasBody = true, status, header, hasBody
	close(f.headCh)
	return nil
}

func (f *fakeResponder) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, len(p))
	return f.body.Write(p)
}

func (f *fakeResponder) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeResponder) Fail(code, message string, retryable bool, origin tunnel.ErrorOrigin) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failure = &tunnel.Error{Code: code, Message: message, Retryable: retryable, Origin: origin}
	return nil
}

func (f *fakeResponder) CancelAck(outcome tunnel.CancelOutcome) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ack = &tunnel.CancelAck{Outcome: outcome}
	return nil
}

func (f *fakeResponder) snapshot() fakeResponder {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeResponder{
		headSent: f.headSent, status: f.status, header: f.header, hasBody: f.hasBody,
		writes: append([]int(nil), f.writes...), closed: f.closed,
		failure: f.failure, ack: f.ack,
	}
}

func (f *fakeResponder) bodyString() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.body.String()
}

// newSecretFile writes a credential file and returns its path.
func newSecretFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatalf("writing secret file: %v", err)
	}
	return path
}

// newExecutor builds an executor pointed at endpoint with a fresh audit buffer.
func newExecutor(t *testing.T, endpoint, secretPath string) (*Executor, *bytes.Buffer) {
	t.Helper()
	args := []string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", "vcsc_abc.def",
		"--endpoint", endpoint,
		"--vendor", "gitlab",
		"--secret-file", secretPath,
		"--instance-key", "connector-0",
		"--all-projects",
	}
	cfg, err := config.Load(args, func(string) string { return "" })
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	engine, err := policy.NewEngine(cfg)
	if err != nil {
		t.Fatalf("policy.NewEngine() error = %v", err)
	}
	var buf bytes.Buffer
	// Debug level: the audit assertions must hold at the most verbose setting.
	audit := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	exec, err := New(cfg, engine, audit)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return exec, &buf
}

// req builds a tunneled request.
func req(method, path, query string) *connect.Request {
	return &connect.Request{
		ID: "stream-1.1",
		Head: &tunnel.HTTPRequest{
			Method:        method,
			Path:          path,
			Query:         query,
			DeadlineClass: tunnel.DeadlineClass_DEADLINE_CLASS_INTERACTIVE,
		},
	}
}

func withHeaders(r *connect.Request, headers map[string][]string) *connect.Request {
	r.Head.Headers = make(map[string]*tunnel.HeaderValues, len(headers))
	for name, values := range headers {
		r.Head.Headers[name] = &tunnel.HeaderValues{Values: values}
	}
	return r
}

func withBody(r *connect.Request, body string) *connect.Request {
	r.Head.HasBody = true
	r.Body = strings.NewReader(body)
	return r
}

// recordingStub is an httptest GitLab that captures what actually arrived.
type recordingStub struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
}

func newStub(t *testing.T, handler http.HandlerFunc) *recordingStub {
	t.Helper()
	s := &recordingStub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.requests = append(s.requests, r.Clone(context.Background()))
		s.bodies = append(s.bodies, string(body))
		s.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *recordingStub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func (s *recordingStub) last() (request *http.Request, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		return nil, ""
	}
	return s.requests[len(s.requests)-1], s.bodies[len(s.bodies)-1]
}

func TestHandle_InjectsCredentialAfterPolicyApproval(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Total", "1")
		_, _ = w.Write([]byte(`{"id":7,"username":"zenfra"}`))
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), w)

	got := w.snapshot()
	if got.failure != nil {
		t.Fatalf("Fail(%q) — want success", got.failure.GetCode())
	}
	if got.status != http.StatusOK {
		t.Errorf("status = %d, want 200", got.status)
	}
	if !got.closed {
		t.Error("response body was never terminated")
	}
	if body := w.bodyString(); body != `{"id":7,"username":"zenfra"}` {
		t.Errorf("body = %q", body)
	}

	upstream, _ := stub.last()
	if token := upstream.Header.Get("PRIVATE-TOKEN"); token != testSecret {
		t.Errorf("PRIVATE-TOKEN = %q, want %q", token, testSecret)
	}
	if ua := upstream.Header.Get("User-Agent"); ua != userAgent {
		t.Errorf("User-Agent = %q, want %q", ua, userAgent)
	}
	if rule := got.header.Get(tunnel.HeaderPolicyRule); rule != "gitlab.user.current" {
		t.Errorf("%s = %q, want gitlab.user.current", tunnel.HeaderPolicyRule, rule)
	}
	if got.header.Get("X-Total") != "1" {
		t.Errorf("allowlisted response header dropped: %v", got.header)
	}
}

// A denial must not even need the credential: the secret file is removed after
// startup validation, so a policy_denied result proves nothing tried to read it.
func TestHandle_DeniedRequestNeverReadsSecretOrReachesUpstream(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	secretPath := newSecretFile(t, testSecret)
	exec, _ := newExecutor(t, stub.srv.URL, secretPath)
	if err := os.Remove(secretPath); err != nil {
		t.Fatalf("removing secret file: %v", err)
	}

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodDelete, "/api/v4/projects/1", ""), w)

	got := w.snapshot()
	if got.failure == nil || got.failure.GetCode() != tunnel.ErrCodePolicyDenied {
		t.Fatalf("failure = %v, want %s", got.failure, tunnel.ErrCodePolicyDenied)
	}
	if got.failure.GetOrigin() != tunnel.ErrorOrigin_ERROR_ORIGIN_CONNECTOR {
		t.Errorf("origin = %v, want connector", got.failure.GetOrigin())
	}
	if got.headSent {
		t.Error("denied request sent a response head")
	}
	if stub.count() != 0 {
		t.Errorf("denied request reached upstream %d times", stub.count())
	}
}

// Driven off rejectedRequestHeaders itself: a header removed from the table
// would otherwise be silently stripped instead of refused, which is exactly the
// laundering the table exists to prevent.
func TestHandle_RejectsInboundCredentialHeaders(t *testing.T) {
	// Deleting a name from the table must fail here too: an entry that is in
	// neither table is silently stripped, which looks like it worked.
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Private-Token",
		"Job-Token", "Deploy-Token", "X-Api-Key", "X-Access-Token", "X-Csrf-Token",
	} {
		if !rejectedRequestHeaders[name] {
			t.Errorf("%s is no longer refused; a credential header must never be stripped instead", name)
		}
	}

	names := []string{"authorization", "PRIVATE-TOKEN"} // casing is not significant
	for name := range rejectedRequestHeaders {
		names = append(names, name)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

			w := newFakeResponder()
			request := withHeaders(req(http.MethodGet, "/api/v4/user", ""),
				map[string][]string{name: {"Bearer stolen"}})
			exec.Handle(context.Background(), request, w)

			got := w.snapshot()
			if got.failure == nil || got.failure.GetCode() != tunnel.ErrCodeProtocol {
				t.Fatalf("failure = %v, want %s", got.failure, tunnel.ErrCodeProtocol)
			}
			if stub.count() != 0 {
				t.Errorf("request with %s header reached upstream", name)
			}
		})
	}
}

func TestHandle_StripsNonForwardableHeaders(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "gitlab")
		_, _ = w.Write([]byte(`{}`))
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	w := newFakeResponder()
	request := withHeaders(req(http.MethodGet, "/api/v4/user", ""), map[string][]string{
		"Accept":          {"application/json"},
		"X-Forwarded-For": {"10.0.0.1"},
		"User-Agent":      {"attacker/1.0"},
		"X-Zenfra-Org":    {"other-org"},
	})
	exec.Handle(context.Background(), request, w)

	upstream, _ := stub.last()
	if got := upstream.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q, want application/json", got)
	}
	for _, dropped := range []string{"X-Forwarded-For", "X-Zenfra-Org"} {
		if got := upstream.Header.Get(dropped); got != "" {
			t.Errorf("%s reached upstream as %q", dropped, got)
		}
	}
	if got := upstream.Header.Get("User-Agent"); got != userAgent {
		t.Errorf("User-Agent = %q, want the connector's own", got)
	}

	got := w.snapshot()
	if cookie := got.header.Get("Set-Cookie"); cookie != "" {
		t.Errorf("Set-Cookie leaked back through the tunnel: %q", cookie)
	}
	if server := got.header.Get("Server"); server != "" {
		t.Errorf("unlisted response header forwarded: %q", server)
	}
}

func TestHandle_NeverFollowsRedirects(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/user" {
			w.Header().Set("Location", "/api/v4/projects")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), w)

	got := w.snapshot()
	if got.status != http.StatusFound {
		t.Errorf("status = %d, want 302", got.status)
	}
	if stub.count() != 1 {
		t.Errorf("upstream hit %d times — the redirect was followed", stub.count())
	}
}

func TestNew_TLSFloorIsTLS12(t *testing.T) {
	exec, _ := newExecutor(t, "https://gitlab.internal", newSecretFile(t, testSecret))
	transport, ok := exec.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", exec.client.Transport)
	}
	if got := transport.TLSClientConfig.MinVersion; got != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want %x", got, tls.VersionTLS12)
	}
}

func TestHandle_RefusesUpstreamBelowTLS12(t *testing.T) {
	var hits int
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS11} //nolint:gosec // deliberately obsolete peer
	srv.StartTLS()
	defer srv.Close()

	exec, _ := newExecutor(t, srv.URL, newSecretFile(t, testSecret))
	// Trust the stub's certificate so only the version floor can fail the dial.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	exec.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), w)

	got := w.snapshot()
	if got.failure == nil {
		t.Fatal("TLS 1.1 upstream was accepted")
	}
	if got.headSent {
		t.Error("response head sent despite a failed handshake")
	}
	if hits != 0 {
		t.Errorf("upstream served %d requests over TLS 1.1", hits)
	}
}

func TestHandle_RequestBodyForwardedAndCapped(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	const path = "/api/v4/projects/1/merge_requests/2/notes"
	w := newFakeResponder()
	exec.Handle(context.Background(), withBody(req(http.MethodPost, path, ""), `{"body":"hi"}`), w)

	if got := w.snapshot(); got.status != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (failure=%v)", got.status, got.failure)
	}
	if _, body := stub.last(); body != `{"body":"hi"}` {
		t.Errorf("upstream body = %q", body)
	}

	exec.limits.MaxRequestBytes = 8
	over := newFakeResponder()
	exec.Handle(context.Background(), withBody(req(http.MethodPost, path, ""), strings.Repeat("x", 64)), over)

	got := over.snapshot()
	if got.failure == nil || got.failure.GetCode() != tunnel.ErrCodeTooLarge {
		t.Fatalf("failure = %v, want %s", got.failure, tunnel.ErrCodeTooLarge)
	}
	if stub.count() != 1 {
		t.Errorf("oversized body reached upstream (%d hits)", stub.count())
	}
}

func TestHandle_ResponseBodyCapRejectedBeforeHead(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		// A declared length lets the cap fire before a single byte is forwarded.
		w.Header().Set("Content-Length", "4096")
		_, _ = w.Write(bytes.Repeat([]byte("a"), 4096))
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))
	exec.limits.MaxResponseBytes = 1024

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), w)

	got := w.snapshot()
	if got.failure == nil || got.failure.GetCode() != tunnel.ErrCodeTooLarge {
		t.Fatalf("failure = %v, want %s", got.failure, tunnel.ErrCodeTooLarge)
	}
	if got.headSent {
		t.Error("head sent for a response known to be too large")
	}
}

// A chunked response has no declared length, so the cap is enforced mid-stream:
// the terminal chunk is withheld so the consumer can never mistake a truncated
// body for a complete one.
func TestHandle_ResponseBodyCapEnforcedMidStream(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		flusher, _ := w.(http.Flusher)
		for range 8 {
			_, _ = w.Write(bytes.Repeat([]byte("a"), 512))
			flusher.Flush()
		}
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))
	exec.limits.MaxResponseBytes = 1024

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), w)

	got := w.snapshot()
	if !got.headSent {
		t.Fatal("head was never sent for a chunked response")
	}
	if got.failure == nil || got.failure.GetCode() != tunnel.ErrCodeTooLarge {
		t.Fatalf("failure = %v, want %s", got.failure, tunnel.ErrCodeTooLarge)
	}
	if got.closed {
		t.Error("terminal chunk sent — a truncated body would look complete")
	}
}

func TestHandle_StreamsResponseInBoundedChunks(t *testing.T) {
	payload := bytes.Repeat([]byte("z"), 100<<10)
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	w := newFakeResponder()
	request := req(http.MethodGet, "/api/v4/projects/1/repository/archive", "")
	request.Head.DeadlineClass = tunnel.DeadlineClass_DEADLINE_CLASS_BULK
	exec.Handle(context.Background(), request, w)

	got := w.snapshot()
	if got.failure != nil {
		t.Fatalf("Fail(%q)", got.failure.GetCode())
	}
	if len(got.writes) < 2 {
		t.Fatalf("body delivered in %d writes — not streamed", len(got.writes))
	}
	for i, n := range got.writes {
		if n > copyBufferBytes {
			t.Fatalf("write %d is %d bytes, want <= %d", i, n, copyBufferBytes)
		}
	}
	if body := w.bodyString(); body != string(payload) {
		t.Errorf("streamed body differs from upstream (%d bytes)", len(body))
	}
	if !got.closed {
		t.Error("stream never terminated")
	}
}

func TestHandle_PreservesEncodedPathAndQuery(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(),
		req(http.MethodGet, "/api/v4/projects/eng%2Fplatform/repository/tree", "ref=main&per_page=100"), w)

	if got := w.snapshot(); got.status != http.StatusOK {
		t.Fatalf("status = %d (failure=%v)", got.status, got.failure)
	}
	upstream, _ := stub.last()
	if got := upstream.URL.EscapedPath(); got != "/api/v4/projects/eng%2Fplatform/repository/tree" {
		t.Errorf("upstream path = %q — the encoded project was rewritten", got)
	}
	if got := upstream.URL.RawQuery; got != "ref=main&per_page=100" {
		t.Errorf("upstream query = %q", got)
	}
}

func TestHandle_NoBodyStatusSendsNoChunks(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(),
		req(http.MethodPut, "/api/v4/projects/1/merge_requests/2/notes/3", ""), w)

	got := w.snapshot()
	if got.status != http.StatusNoContent {
		t.Fatalf("status = %d (failure=%v)", got.status, got.failure)
	}
	if got.hasBody || len(got.writes) != 0 {
		t.Errorf("204 announced a body: hasBody=%v writes=%v", got.hasBody, got.writes)
	}
}

func TestHandle_SecretFileReloadedOnChange(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	secretPath := newSecretFile(t, "token-one")
	exec, _ := newExecutor(t, stub.srv.URL, secretPath)

	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), newFakeResponder())
	if upstream, _ := stub.last(); upstream.Header.Get("PRIVATE-TOKEN") != "token-one" {
		t.Fatalf("first token = %q", upstream.Header.Get("PRIVATE-TOKEN"))
	}

	// Rotation: the operator swaps the file in place.
	if err := os.WriteFile(secretPath, []byte("token-two\n"), 0o600); err != nil {
		t.Fatalf("rotating secret: %v", err)
	}
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), newFakeResponder())
	if upstream, _ := stub.last(); upstream.Header.Get("PRIVATE-TOKEN") != "token-two" {
		t.Errorf("token after rotation = %q, want token-two", upstream.Header.Get("PRIVATE-TOKEN"))
	}
}

// A secret that becomes unusable after startup — a rotation that deleted or
// blanked the file — must fail the request before it is dispatched. New()
// refuses an unreadable file outright, so the damage happens post-construction.
func TestHandle_UnusableSecretFailsWithoutDispatch(t *testing.T) {
	tests := map[string]func(t *testing.T, path string){
		"missing": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatalf("removing secret file: %v", err)
			}
		},
		"empty": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
				t.Fatalf("blanking secret file: %v", err)
			}
		},
	}
	for name, breakSecret := range tests {
		t.Run(name, func(t *testing.T) {
			stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			secretPath := newSecretFile(t, testSecret)
			exec, _ := newExecutor(t, stub.srv.URL, secretPath)
			breakSecret(t, secretPath)

			w := newFakeResponder()
			exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), w)

			got := w.snapshot()
			if got.failure == nil || got.failure.GetCode() != tunnel.ErrCodeAuth {
				t.Fatalf("failure = %v, want %s", got.failure, tunnel.ErrCodeAuth)
			}
			if stub.count() != 0 {
				t.Error("request dispatched without a credential")
			}
		})
	}
}

func TestHandle_UpstreamTimeout(t *testing.T) {
	release := make(chan struct{})
	stub := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	})
	defer close(release)

	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))
	exec.limits.InteractiveTimeout = 50 * time.Millisecond

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), w)

	got := w.snapshot()
	if got.failure == nil || got.failure.GetCode() != tunnel.ErrCodeUpstreamTimeout {
		t.Fatalf("failure = %v, want %s", got.failure, tunnel.ErrCodeUpstreamTimeout)
	}
	if got.failure.GetOrigin() != tunnel.ErrorOrigin_ERROR_ORIGIN_UPSTREAM {
		t.Errorf("origin = %v, want upstream", got.failure.GetOrigin())
	}
}

// connect.Responder wraps an unexported *Conn, so the closure cannot be driven
// from here; the return type is the compile-time proof and this guards a nil one.
// Handler's body is exercised end-to-end by the connect package's own tests.
func TestHandler_MatchesConnectSignature(t *testing.T) {
	exec, _ := newExecutor(t, "https://gitlab.internal", newSecretFile(t, testSecret))
	handler := exec.Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}
}

// auditLines splits the captured audit output into parsed records.
func auditLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit line is not JSON: %v (%q)", err, line)
		}
		records = append(records, rec)
	}
	return records
}

func TestAudit_OneRecordPerRequest(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":7}`))
	})
	exec, out := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	exec.Handle(context.Background(),
		req(http.MethodGet, "/api/v4/projects/9/merge_requests/2/notes", "per_page=20"), newFakeResponder())
	exec.Handle(context.Background(), req(http.MethodDelete, "/api/v4/projects/9", ""), newFakeResponder())

	records := auditLines(t, out.String())
	if len(records) != 2 {
		t.Fatalf("got %d audit records, want 2:\n%s", len(records), out.String())
	}

	allow := records[0]
	for key, want := range map[string]any{
		"decision": "allow",
		"rule":     "gitlab.merge_request.notes.list",
		"purpose":  "List Merge Request Comments",
		"project":  "9",
		"method":   http.MethodGet,
		"path":     "/api/v4/projects/9/merge_requests/2/notes",
		"lane":     "interactive",
		"status":   float64(http.StatusOK),
	} {
		if got := allow[key]; got != want {
			t.Errorf("allow record %s = %v, want %v", key, got, want)
		}
	}
	if _, ok := allow["elapsed_ms"]; !ok {
		t.Errorf("allow record has no elapsed_ms: %v", allow)
	}

	deny := records[1]
	if deny["decision"] != "deny" {
		t.Errorf("deny record decision = %v", deny["decision"])
	}
	if deny["error"] != tunnel.ErrCodePolicyDenied {
		t.Errorf("deny record error = %v, want %s", deny["error"], tunnel.ErrCodePolicyDenied)
	}
	if reason, _ := deny["reason"].(string); reason == "" {
		t.Error("deny record carries no reason")
	}
}

// The audit log must be safe to ship at any level: no header, body or token ever
// becomes a field, so the most verbose setting still leaks nothing.
func TestAudit_NeverContainsAuthMaterial(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "session=upstream-cookie-value")
		_, _ = w.Write([]byte(`{"private_token":"body-secret-value"}`))
	})
	exec, out := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	// An allowed call, a denied call, and one carrying an inbound credential.
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), newFakeResponder())
	exec.Handle(context.Background(), req(http.MethodPost, "/api/v4/admin/users", ""), newFakeResponder())
	exec.Handle(context.Background(),
		withHeaders(req(http.MethodGet, "/api/v4/user", ""),
			map[string][]string{"Authorization": {"Bearer inbound-bearer-value"}}), newFakeResponder())

	logged := out.String()
	for _, secret := range []string{
		testSecret, "upstream-cookie-value", "body-secret-value", "inbound-bearer-value",
	} {
		if strings.Contains(logged, secret) {
			t.Errorf("audit log contains %q:\n%s", secret, logged)
		}
	}
	if n := len(auditLines(t, logged)); n != 3 {
		t.Errorf("got %d audit records, want 3", n)
	}
}

// newExecutorWithArgs builds an executor with extra flags appended.
func newExecutorWithArgs(t *testing.T, endpoint, secretPath string, extra ...string) *Executor {
	t.Helper()
	args := append([]string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", "vcsc_abc.def",
		"--endpoint", endpoint,
		"--vendor", "gitlab",
		"--secret-file", secretPath,
		"--instance-key", "connector-0",
		"--all-projects",
	}, extra...)
	cfg, err := config.Load(args, func(string) string { return "" })
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	engine, err := policy.NewEngine(cfg)
	if err != nil {
		t.Fatalf("policy.NewEngine() error = %v", err)
	}
	exec, err := New(cfg, engine, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return exec
}

// writeCertPEM writes a server certificate out as a PEM trust bundle.
func writeCertPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "upstream-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestHandle_UpstreamCABundle covers the common private-VCS deployment: the
// customer's GitLab is signed by an internal CA the system roots know nothing
// about. Without the bundle the handshake must fail (no silent skip-verify);
// with it the same request must succeed.
func TestHandle_UpstreamCABundle(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"username":"svc"}`))
	}))
	defer srv.Close()
	secret := newSecretFile(t, testSecret)

	t.Run("untrusted issuer is refused", func(t *testing.T) {
		w := newFakeResponder()
		newExecutorWithArgs(t, srv.URL, secret).
			Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), w)

		got := w.snapshot()
		if got.failure == nil {
			t.Fatal("an unknown issuer was accepted without a trust bundle")
		}
		if got.failure.Code != tunnel.ErrCodeUpstreamTLS {
			t.Errorf("error code = %q, want %q", got.failure.Code, tunnel.ErrCodeUpstreamTLS)
		}
	})

	t.Run("bundled issuer is trusted", func(t *testing.T) {
		w := newFakeResponder()
		newExecutorWithArgs(t, srv.URL, secret,
			"--upstream-ca-bundle", writeCertPEM(t, srv.Certificate())).
			Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), w)

		got := w.snapshot()
		if got.failure != nil {
			t.Fatalf("bundled CA still failed: %+v", got.failure)
		}
		if got.status != http.StatusOK {
			t.Errorf("status = %d, want 200", got.status)
		}
		if body := w.bodyString(); !strings.Contains(body, "svc") {
			t.Errorf("body = %q, want the upstream reply", body)
		}
	})

	t.Run("unreadable bundle is a terminal misconfiguration", func(t *testing.T) {
		cfg, err := config.Load([]string{
			"--gateway-url", "https://api.zenfra.cloud",
			"--bootstrap-token", "vcsc_abc.def",
			"--endpoint", srv.URL,
			"--vendor", "gitlab",
			"--secret-file", secret,
			"--instance-key", "connector-0",
			"--all-projects",
			"--upstream-ca-bundle", filepath.Join(t.TempDir(), "missing.pem"),
		}, func(string) string { return "" })
		if err != nil {
			t.Fatalf("config.Load() error = %v", err)
		}
		engine, err := policy.NewEngine(cfg)
		if err != nil {
			t.Fatalf("policy.NewEngine() error = %v", err)
		}
		if _, err := New(cfg, engine, nil); err == nil {
			t.Fatal("a missing CA bundle must fail at startup, not per request")
		}
	})
}

// SECURITY: the allowlist's promise is that the string it matched is the string
// that reaches the VCS. A byte Go escapes in paths (here a space) makes url.Parse
// drop the raw form, so EscapedPath re-derives it from the decoded path and the
// approved %2F becomes a real separator — a different project. The request must
// fail rather than be sent under a path the policy never saw.
func TestHandle_PathThatWouldBeReEscapedIsRefused(t *testing.T) {
	upstream := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	exec, _ := newExecutor(t, upstream.srv.URL, newSecretFile(t, "glpat-secret"))

	w := newFakeResponder()
	exec.Handle(context.Background(),
		req(http.MethodGet, "/api/v4/projects/eng%2Fplatform/repository/branches/a b", ""), w)

	if got := w.snapshot(); got.failure == nil {
		t.Fatalf("status = %d, want the request refused", got.status)
	}
	if n := upstream.count(); n != 0 {
		followed, _ := upstream.last()
		t.Fatalf("upstream received %d requests (path %q), want none", n, followed.URL.EscapedPath())
	}
}
