// ABOUTME: Upstream HTTP executor: runs policy-approved tunneled requests against the customer's VCS.
// ABOUTME: Injects the local credential only after approval, never redirects, streams the reply in chunks.
package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/connect"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/metrics"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/policy"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// Credential headers per vendor. The value is read from the local secret file per
// request and never leaves this process except on the upstream leg.
const (
	gitLabTokenHeader = "PRIVATE-TOKEN"
	gitHubAuthHeader  = "Authorization"
	gitHubAuthScheme  = "Bearer "
	// Azure DevOps authenticates a PAT as HTTP Basic with an empty username.
	azureDevOpsAuthScheme = "Basic "
)

// maxRedirectsFollowed is the number of redirects the connector resolves itself:
// exactly one, onto a pinned origin, for the rules that declare it.
const maxRedirectsFollowed = 1

// userAgent identifies the connector to the upstream VCS.
const userAgent = "zenfra-vcs-connector"

// copyBufferBytes bounds the response streaming buffer, so a 100 MiB archive
// costs 32 KiB of connector memory.
const copyBufferBytes = tunnel.DefaultChunkBytes

// Limits bound one tunneled exchange.
type Limits struct {
	// MaxRequestBytes caps a buffered request body (MR comments, commit statuses).
	MaxRequestBytes int64
	// MaxResponseBytes caps an interactive response body.
	MaxResponseBytes int64
	// MaxBulkResponseBytes caps a bulk-lane response body (repository archives).
	MaxBulkResponseBytes int64
	// InteractiveTimeout and BulkTimeout bound the upstream call per deadline
	// class. Both sit under the gateway's own budget (10s / 10m) so the connector
	// loses the race and the caller gets a typed upstream_timeout instead of a
	// generic gateway deadline.
	InteractiveTimeout time.Duration
	BulkTimeout        time.Duration
}

// DefaultLimits returns the Phase 1 bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxRequestBytes:      1 << 20,
		MaxResponseBytes:     16 << 20,
		MaxBulkResponseBytes: 100 << 20,
		InteractiveTimeout:   9 * time.Second,
		BulkTimeout:          9 * time.Minute,
	}
}

func (l Limits) timeoutFor(class tunnel.DeadlineClass) time.Duration {
	if class == tunnel.DeadlineClass_DEADLINE_CLASS_BULK {
		return l.BulkTimeout
	}
	return l.InteractiveTimeout
}

func (l Limits) responseCapFor(class tunnel.DeadlineClass) int64 {
	if class == tunnel.DeadlineClass_DEADLINE_CLASS_BULK {
		return l.MaxBulkResponseBytes
	}
	return l.MaxResponseBytes
}

// Responder is the subset of *connect.Responder the executor drives. It exists so
// the executor is testable without a live tunnel connection.
type Responder interface {
	Head(status int, header http.Header, hasBody bool) error
	Write(p []byte) (int, error)
	Close() error
	Fail(code, message string, retryable bool, origin tunnel.ErrorOrigin) error
	CancelAck(outcome tunnel.CancelOutcome) error
}

// Executor serves tunneled requests against one upstream VCS endpoint.
type Executor struct {
	vendor config.Vendor
	// origins are the base URLs the operator pinned at startup, keyed by the
	// origin a policy rule names. Nothing on the wire can add or change one.
	origins    map[policy.Origin]string
	secretFile string
	engine     *policy.Engine
	client     *http.Client
	limits     Limits
	audit      *slog.Logger
	// Metrics is the optional Prometheus collector; nil disables it.
	Metrics *metrics.Collector
}

// New builds an executor for the configured endpoint. audit receives exactly one
// structured record per request; pass a JSON handler.
func New(cfg *config.Config, engine *policy.Engine, audit *slog.Logger) (*Executor, error) {
	if engine == nil {
		return nil, errors.New("executor: policy engine is required")
	}
	if audit == nil {
		audit = slog.Default()
	}

	// SECURITY: the SSRF-safe dialer from the control plane's GitLab client is
	// deliberately NOT copied here — it blocks private address space, which is
	// exactly where the connector's upstream lives. The equivalent guarantee comes
	// from structure instead: the host is pinned by --endpoint at startup and the
	// tunnel carries a path only, so no wire input can retarget the request.
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("executor: default transport has unexpected type")
	}
	transport := baseTransport.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.ForceAttemptHTTP2 = true
	if cfg.UpstreamCABundle != "" {
		// Fail at startup, not per request: a bundle the operator cannot read is
		// a flag problem, and every tunneled request would fail identically.
		tlsCfg, err := connect.TLSConfigFromCABundle(cfg.UpstreamCABundle)
		if err != nil {
			return nil, fmt.Errorf("executor: upstream CA bundle: %w", err)
		}
		transport.TLSClientConfig = tlsCfg
	}

	origins := map[policy.Origin]string{
		policy.OriginPrimary:  strings.TrimSuffix(cfg.Endpoint, "/"),
		policy.OriginCodeload: strings.TrimSuffix(cfg.Endpoint, "/"),
	}
	if cfg.CodeloadEndpoint != "" {
		origins[policy.OriginCodeload] = strings.TrimSuffix(cfg.CodeloadEndpoint, "/")
	}

	return &Executor{
		vendor:     cfg.Vendor,
		origins:    origins,
		secretFile: cfg.SecretFile,
		engine:     engine,
		limits:     DefaultLimits(),
		audit:      audit,
		client: &http.Client{
			Transport: transport,
			// SECURITY: never follow redirects — a redirect would replay the
			// injected credential against a host the allowlist never approved.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Handler adapts the executor to the tunnel connection's handler signature.
func (e *Executor) Handler() connect.Handler {
	return func(ctx context.Context, req *connect.Request, w *connect.Responder) {
		e.Handle(ctx, req, w)
	}
}

// exchange phases, used to answer a cancel with the true terminal state.
const (
	// phaseNotSent: the upstream request has not left the connector.
	phaseNotSent = iota
	// phaseInFlight: the request was sent but no status came back, so whether it
	// took effect upstream is unknowable from here.
	phaseInFlight
	// phaseCompleted: a status line arrived, so the upstream effect has happened
	// even if the body is still streaming.
	phaseCompleted
)

// Handle serves one tunneled request: evaluate, inject, execute, stream back.
func (e *Executor) Handle(ctx context.Context, req *connect.Request, w Responder) {
	head := req.Head
	rec := &auditRecord{
		RequestID: req.ID,
		Method:    head.GetMethod(),
		Lane:      laneName(head.GetDeadlineClass()),
		Decision:  decisionDeny,
	}
	start := time.Now()
	defer func() { e.log(rec, time.Since(start)) }()

	// A credential arriving from the control plane is either a bug or an attempt
	// to ride this connector's upstream session; it is refused before the request
	// is even evaluated.
	if name := credentialHeader(head.GetHeaders()); name != "" {
		rec.Reason = "inbound " + name + " header is not accepted"
		e.fail(w, rec, tunnel.ErrCodeProtocol, rec.Reason, false, tunnel.ErrorOrigin_ERROR_ORIGIN_CONNECTOR)
		return
	}

	dec := e.engine.Evaluate(head.GetMethod(), head.GetPath(), head.GetQuery())
	rec.Rule, rec.Purpose, rec.Project = dec.RuleID, dec.Purpose, dec.Project
	if !dec.Allowed {
		rec.Reason = dec.Reason
		e.fail(w, rec, tunnel.ErrCodePolicyDenied, dec.Reason, false, tunnel.ErrorOrigin_ERROR_ORIGIN_CONNECTOR)
		return
	}
	rec.Decision = decisionAllow
	rec.Path, rec.Query = dec.Path, dec.Query

	body, ok := e.readRequestBody(req, w, rec)
	if !ok {
		return
	}

	timeout := e.limits.timeoutFor(head.GetDeadlineClass())
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := e.buildRequest(callCtx, &dec, head, body)
	if err != nil {
		rec.Reason = err.Error()
		e.fail(w, rec, tunnel.ErrCodeAuth, err.Error(), false, tunnel.ErrorOrigin_ERROR_ORIGIN_CONNECTOR)
		return
	}

	if ctx.Err() != nil {
		// Cancelled while we were preparing: nothing reached the upstream.
		e.ack(w, rec, tunnel.CancelOutcome_CANCEL_OUTCOME_NOT_SENT)
		return
	}

	phase := phaseInFlight
	resp, err := e.client.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			e.ack(w, rec, cancelOutcome(phase))
			return
		}
		code, message := classifyUpstreamError(err, callCtx)
		rec.Reason = message
		e.fail(w, rec, code, message, code != tunnel.ErrCodeUpstreamTLS, tunnel.ErrorOrigin_ERROR_ORIGIN_UPSTREAM)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	phase = phaseCompleted
	rec.Status = resp.StatusCode

	for followed := 0; dec.RedirectsTo != "" && followed < maxRedirectsFollowed &&
		isRedirect(resp.StatusCode); followed++ {
		next := e.followPinnedRedirect(callCtx, &dec, resp, w, rec)
		if next == nil {
			return
		}
		// Close the redirect before replacing it; the deferred close follows the
		// variable and would otherwise only reach the last response.
		_ = resp.Body.Close()
		resp = next
	}

	e.stream(ctx, &dec, head, resp, w, rec, phase)
}

// readRequestBody buffers the request body under the cap. Bodies here are MR
// comments and commit statuses; buffering keeps the too-large check ahead of
// dispatch, so an oversized body never reaches the upstream at all.
func (e *Executor) readRequestBody(req *connect.Request, w Responder, rec *auditRecord) ([]byte, bool) {
	if !req.Head.GetHasBody() || req.Body == nil {
		return nil, true
	}
	buf, err := io.ReadAll(io.LimitReader(req.Body, e.limits.MaxRequestBytes+1))
	if err != nil {
		rec.Reason = "reading tunneled request body: " + err.Error()
		e.fail(w, rec, tunnel.ErrCodeProtocol, rec.Reason, false, tunnel.ErrorOrigin_ERROR_ORIGIN_CONNECTOR)
		return nil, false
	}
	if int64(len(buf)) > e.limits.MaxRequestBytes {
		rec.Reason = fmt.Sprintf("request body exceeds %d bytes", e.limits.MaxRequestBytes)
		e.fail(w, rec, tunnel.ErrCodeTooLarge, rec.Reason, false, tunnel.ErrorOrigin_ERROR_ORIGIN_CONNECTOR)
		return nil, false
	}
	rec.RequestBytes = int64(len(buf))
	return buf, true
}

// buildRequest assembles the upstream call from the approved decision and injects
// the credential. The path and query are the exact bytes the allowlist matched.
func (e *Executor) buildRequest(
	ctx context.Context, dec *policy.Decision, head *tunnel.HTTPRequest, body []byte,
) (*http.Request, error) {
	origin, ok := e.origins[dec.Origin]
	if !ok {
		return nil, fmt.Errorf("no endpoint is configured for origin %q", dec.Origin)
	}
	target := origin + dec.Path
	if dec.Query != "" {
		target += "?" + dec.Query
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, dec.Method, target, reader)
	if err != nil {
		return nil, fmt.Errorf("building upstream request: %w", err)
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}

	for name, values := range head.GetHeaders() {
		canonical := http.CanonicalHeaderKey(name)
		if !forwardableRequestHeaders[canonical] {
			continue
		}
		for _, value := range values.GetValues() {
			req.Header.Add(canonical, value)
		}
	}
	req.Header.Set("User-Agent", userAgent)

	// The credential is read here and only here: after the allowlist approved the
	// request, and never for a denied one. An alternate origin is a different host
	// in general, and its URL is already authorized by the redirect that named it,
	// so the credential stays on the primary leg.
	if dec.Origin == policy.OriginPrimary {
		token, err := readSecret(e.secretFile)
		if err != nil {
			return nil, err
		}
		e.authorize(req, token)
	}
	return req, nil
}

// authorize attaches the vendor's credential header. GitHub Enterprise and
// Bitbucket Data Center both authenticate their tokens as bearer credentials,
// Azure DevOps takes its PAT as HTTP Basic with an empty username, and GitLab
// uses its own header.
func (e *Executor) authorize(req *http.Request, token string) {
	switch e.vendor {
	case config.VendorGitHub, config.VendorBitbucket:
		req.Header.Set(gitHubAuthHeader, gitHubAuthScheme+token)
	case config.VendorAzureDevOps:
		encoded := base64.StdEncoding.EncodeToString([]byte(":" + token))
		req.Header.Set(gitHubAuthHeader, azureDevOpsAuthScheme+encoded)
	default:
		req.Header.Set(gitLabTokenHeader, token)
	}
}

// followPinnedRedirect resolves a redirect the matched rule allows. Only the path
// and query of the Location are used: the request is re-evaluated against the
// allowlist and sent to the origin the operator pinned, so a Location naming
// another host moves nothing. Returns the replacement response, or nil after
// having failed the exchange.
func (e *Executor) followPinnedRedirect(
	ctx context.Context, dec *policy.Decision, resp *http.Response, w Responder, rec *auditRecord,
) *http.Response {
	location := resp.Header.Get("Location")
	if location == "" {
		rec.Reason = "upstream redirect carried no Location"
		e.fail(w, rec, tunnel.ErrCodeUpstreamHTTP, rec.Reason, false, tunnel.ErrorOrigin_ERROR_ORIGIN_UPSTREAM)
		return nil
	}
	target, err := url.Parse(location)
	if err != nil {
		rec.Reason = "upstream redirect Location is not a URL"
		e.fail(w, rec, tunnel.ErrCodeUpstreamHTTP, rec.Reason, false, tunnel.ErrorOrigin_ERROR_ORIGIN_UPSTREAM)
		return nil
	}

	next := e.engine.Evaluate(http.MethodGet, target.EscapedPath(), target.RawQuery)
	if !next.Allowed || next.Origin != dec.RedirectsTo {
		rec.Reason = redirectDenialReason(&next, dec.RedirectsTo)
		e.fail(w, rec, tunnel.ErrCodePolicyDenied, rec.Reason, false, tunnel.ErrorOrigin_ERROR_ORIGIN_CONNECTOR)
		return nil
	}
	rec.RedirectOrigin = string(next.Origin)

	followed, err := e.buildRequest(ctx, &next, nil, nil)
	if err != nil {
		rec.Reason = err.Error()
		e.fail(w, rec, tunnel.ErrCodeProtocol, rec.Reason, false, tunnel.ErrorOrigin_ERROR_ORIGIN_CONNECTOR)
		return nil
	}
	next2, err := e.client.Do(followed)
	if err != nil {
		code, message := classifyUpstreamError(err, ctx)
		rec.Reason = message
		e.fail(w, rec, code, message, code != tunnel.ErrCodeUpstreamTLS, tunnel.ErrorOrigin_ERROR_ORIGIN_UPSTREAM)
		return nil
	}
	rec.Status = next2.StatusCode
	return next2
}

// redirectDenialReason explains a refused redirect without echoing the Location:
// an upstream-controlled string has no place in the connector's audit log.
func redirectDenialReason(next *policy.Decision, want policy.Origin) string {
	if !next.Allowed {
		return "upstream redirect target is not allowlisted: " + next.Reason
	}
	return fmt.Sprintf("upstream redirect target belongs to origin %q, want %q", next.Origin, want)
}

// isRedirect reports whether a status carries a Location worth resolving.
func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// stream forwards the response head and body back through the tunnel.
func (e *Executor) stream(
	ctx context.Context,
	dec *policy.Decision,
	head *tunnel.HTTPRequest,
	resp *http.Response,
	w Responder,
	rec *auditRecord,
	phase int,
) {
	capBytes := e.limits.responseCapFor(head.GetDeadlineClass())
	if resp.ContentLength > capBytes {
		rec.Reason = fmt.Sprintf("response body exceeds %d bytes", capBytes)
		e.fail(w, rec, tunnel.ErrCodeTooLarge, rec.Reason, false, tunnel.ErrorOrigin_ERROR_ORIGIN_UPSTREAM)
		return
	}

	header := filterResponseHeaders(resp.Header)
	dec.StampHeader(header)
	hasBody := responseHasBody(dec.Method, resp.StatusCode)
	if err := w.Head(resp.StatusCode, header, hasBody); err != nil {
		rec.Reason = "sending response head: " + err.Error()
		return
	}
	if !hasBody {
		return
	}

	written, err := io.CopyBuffer(
		writerFunc(w.Write), io.LimitReader(resp.Body, capBytes+1), make([]byte, copyBufferBytes),
	)
	rec.ResponseBytes = written
	switch {
	case written > capBytes:
		// ponytail: the terminal chunk is deliberately withheld so the gateway
		// fails this download on its own deadline rather than handing a consumer a
		// silently truncated body. Streaming a mid-body error cleanly needs a
		// protocol message the v1 envelope does not have.
		rec.Reason = fmt.Sprintf("response body exceeds %d bytes", capBytes)
		e.fail(w, rec, tunnel.ErrCodeTooLarge, rec.Reason, false, tunnel.ErrorOrigin_ERROR_ORIGIN_UPSTREAM)
		return
	case err != nil:
		if ctx.Err() != nil {
			e.ack(w, rec, cancelOutcome(phase))
			return
		}
		rec.Reason = "streaming response body: " + err.Error()
		e.fail(w, rec, tunnel.ErrCodeUpstreamConn, rec.Reason, false, tunnel.ErrorOrigin_ERROR_ORIGIN_UPSTREAM)
		return
	}
	if err := w.Close(); err != nil {
		rec.Reason = "closing response body: " + err.Error()
	}
}

// fail ends the exchange with a typed error and records why.
func (e *Executor) fail(
	w Responder, rec *auditRecord, code, message string, retryable bool, origin tunnel.ErrorOrigin,
) {
	rec.Error = code
	if err := w.Fail(code, message, retryable, origin); err != nil {
		rec.Reason = rec.Reason + "; " + err.Error()
	}
}

// ack answers a cancel with the exchange's true terminal state.
func (e *Executor) ack(w Responder, rec *auditRecord, outcome tunnel.CancelOutcome) {
	rec.Error = tunnel.ErrCodeCancelled
	rec.Cancelled = outcome.String()
	_ = w.CancelAck(outcome)
}

func cancelOutcome(phase int) tunnel.CancelOutcome {
	switch phase {
	case phaseNotSent:
		return tunnel.CancelOutcome_CANCEL_OUTCOME_NOT_SENT
	case phaseCompleted:
		return tunnel.CancelOutcome_CANCEL_OUTCOME_COMPLETED
	default:
		return tunnel.CancelOutcome_CANCEL_OUTCOME_OUTCOME_UNKNOWN
	}
}

// classifyUpstreamError maps a transport failure onto a stable wire code.
func classifyUpstreamError(err error, callCtx context.Context) (code, message string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded) || callCtx.Err() != nil:
		return tunnel.ErrCodeUpstreamTimeout, "upstream request timed out"
	case isTLSError(err):
		return tunnel.ErrCodeUpstreamTLS, "upstream TLS handshake failed"
	case isDNSError(err):
		return tunnel.ErrCodeUpstreamDNS, "upstream host could not be resolved"
	default:
		return tunnel.ErrCodeUpstreamConn, "upstream connection failed"
	}
}

func isTLSError(err error) bool {
	var recordErr *tls.RecordHeaderError
	var certErr *tls.CertificateVerificationError
	var alert tls.AlertError
	return errors.As(err, &recordErr) || errors.As(err, &certErr) || errors.As(err, &alert)
}

func isDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

// responseHasBody reports whether body chunks follow the head, per RFC 9110.
func responseHasBody(method string, status int) bool {
	if strings.EqualFold(method, http.MethodHead) {
		return false
	}
	return status != http.StatusNoContent && status != http.StatusNotModified &&
		(status < 100 || status >= 200)
}

// readSecret loads the upstream credential from disk.
//
// ponytail: read per request rather than cached with an mtime check — a local
// read is orders of magnitude cheaper than the network call it precedes, a
// rotated secret takes effect on the very next request, and there is no cache to
// invalidate wrongly. Atomicity comes from the writer: Kubernetes and
// `mv`-style rotations swap the file, so a read sees the old or new bytes, never
// a partial write.
func readSecret(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the operator chooses the secret path
	if err != nil {
		// The path is safe to name; the contents never are.
		return "", fmt.Errorf("reading secret file %s: %w", path, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return token, nil
}

// writerFunc adapts a Write method to io.Writer without exposing the Responder's
// other methods to io.CopyBuffer (which would otherwise look for ReadFrom).
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
