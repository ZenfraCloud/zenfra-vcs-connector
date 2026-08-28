// ABOUTME: Local webhook listener the customer's VCS posts to inside their own network.
// ABOUTME: Verifies the shared secret, then relays the body up the tunnel as an Event.

package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// Path is the endpoint the customer points their VCS webhook at.
const Path = "/webhook"

// relayTimeout bounds one upstream relay. It sits under a vendor's own delivery
// timeout so the connector answers before the vendor gives up on it.
const relayTimeout = 10 * time.Second

// Vendor header names. GitLab authenticates with the secret token verbatim,
// GitHub Enterprise and Bitbucket Data Center sign the body with HMAC-SHA256 (on
// different headers), and Azure DevOps uses HTTP Basic.
const (
	headerGitLabToken     = "X-Gitlab-Token" // #nosec G101 -- header name, not a credential
	headerGitLabEvent     = "X-Gitlab-Event"
	headerGitLabDelivery  = "X-Gitlab-Event-UUID"
	headerHubSignature256 = "X-Hub-Signature-256"
	// headerHubSignature is Bitbucket Data Center's signature header. It carries
	// the same "sha256=<hex>" body HMAC as GitHub's -256 variant.
	headerHubSignature   = "X-Hub-Signature"
	headerGitHubEvent    = "X-GitHub-Event"
	headerGitHubDelivery = "X-GitHub-Delivery"
	headerBitbucketEvent = "X-Event-Key"
	// headerRequestID is the delivery identity for the two vendors that ship no
	// dedicated delivery header.
	headerRequestID     = "X-Request-Id"
	hmacSignaturePrefix = "sha256="
	// azureDevOpsEventType is fixed: a service hook subscription is per event
	// type, so the request itself never names one.
	azureDevOpsEventType = "push"
)

// Relay sends one event up the tunnel and reports the gateway's answer.
// Satisfied by *connect.Manager.
type Relay interface {
	SendEvent(ctx context.Context, event *tunnel.Event) (*tunnel.EventAck, error)
}

// Listener serves the local webhook endpoint for one connector instance.
type Listener struct {
	vendor config.Vendor
	secret []byte
	relay  Relay
	logger *slog.Logger
}

// NewListener builds the listener. secret is the shared value the vendor is
// configured with; an empty one is refused because an unauthenticated listener
// inside the customer's network would let anything on it trigger runs.
func NewListener(
	vendor config.Vendor,
	secret string,
	relay Relay,
	logger *slog.Logger,
) (*Listener, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("webhook: a secret is required")
	}
	if relay == nil {
		return nil, errors.New("webhook: a relay is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Listener{
		vendor: vendor,
		secret: []byte(secret),
		relay:  relay,
		logger: logger.With("component", "webhook"),
	}, nil
}

// Handler mounts the listener on its own mux.
func (l *Listener) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST "+Path, l)
	return mux
}

// ServeHTTP verifies one delivery and relays it. The status codes are the ones
// every vendor understands: 202 accepted, 401 rejected, 503 try again.
func (l *Listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, tunnel.MaxEventBytes))
	if err != nil {
		// Logged, unlike the other refusals: no vendor retries a 413, so without
		// a record the delivery simply vanishes with nothing to point at.
		l.logger.Warn("refused an oversized webhook delivery",
			"limit_bytes", tunnel.MaxEventBytes, "error", err)
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !l.verify(r.Header, body) {
		// Deliberately uninformative: a probe learns only that it failed.
		l.logger.Warn("rejected a webhook delivery with a bad secret")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	eventType, deliveryID := l.identify(r.Header)
	if eventType == "" || deliveryID == "" {
		http.Error(w, "missing event type or delivery id", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), relayTimeout)
	defer cancel()
	ack, err := l.relay.SendEvent(ctx, &tunnel.Event{
		Vendor:     string(l.vendor),
		EventType:  eventType,
		DeliveryId: deliveryID,
		Payload:    body,
	})
	if err != nil {
		// The tunnel is down or the gateway never answered. Ask the vendor to
		// redeliver rather than swallow the push.
		l.logger.Warn("could not relay a webhook delivery",
			"event_type", eventType, "delivery_id", deliveryID, "error", err)
		http.Error(w, "tunnel unavailable", http.StatusServiceUnavailable)
		return
	}
	if !ack.GetAccepted() {
		l.logger.Info("the control plane refused a webhook delivery",
			"event_type", eventType, "delivery_id", deliveryID,
			"code", ack.GetCode(), "message", ack.GetMessage())
		if ack.GetCode() != tunnel.ErrCodePolicyDenied {
			// Only policy_denied is final. connector_busy (the gateway's
			// in-flight cap) and protocol (a transient control-plane failure)
			// both want the vendor to redeliver; 204 would tell it the push
			// landed and the run would simply never happen.
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		// A policy refusal is final — a redelivery would be refused identically.
		w.WriteHeader(http.StatusNoContent)
		return
	}

	l.logger.Info("relayed a webhook delivery",
		"event_type", eventType, "delivery_id", deliveryID)
	w.WriteHeader(http.StatusAccepted)
}

// verify authenticates one delivery against the configured secret. Each vendor
// is checked only in the shape it actually sends, so a signed vendor cannot be
// downgraded to the weaker verbatim-token comparison by omitting its signature.
func (l *Listener) verify(header http.Header, body []byte) bool {
	switch l.vendor {
	case config.VendorGitHub:
		return verifyHMAC(l.secret, header.Get(headerHubSignature256), body)
	case config.VendorBitbucket:
		return verifyHMAC(l.secret, header.Get(headerHubSignature), body)
	case config.VendorAzureDevOps:
		// Service hooks carry no signature; a subscription authenticates with
		// HTTP Basic, so the password is the shared secret.
		_, password, ok := (&http.Request{Header: header}).BasicAuth()
		return ok && hmac.Equal([]byte(password), l.secret)
	case config.VendorGitLab:
		// GitLab sends the secret verbatim; compare in constant time all the same.
		token := header.Get(headerGitLabToken)
		return token != "" && hmac.Equal([]byte(token), l.secret)
	}
	return false
}

// verifyHMAC checks a "sha256=<hex>" body signature.
func verifyHMAC(secret []byte, signature string, body []byte) bool {
	hexDigest, ok := strings.CutPrefix(signature, hmacSignaturePrefix)
	if !ok {
		return false
	}
	got, err := hex.DecodeString(hexDigest)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// identify pulls the vendor's event type and delivery ID out of the headers.
// The delivery ID is what keeps a redelivery from triggering twice, so a
// delivery without one is refused rather than relayed unidentified.
func (l *Listener) identify(header http.Header) (eventType, deliveryID string) {
	switch l.vendor {
	case config.VendorGitLab:
		return normalizeEventType(header.Get(headerGitLabEvent)), header.Get(headerGitLabDelivery)
	case config.VendorGitHub:
		return header.Get(headerGitHubEvent), header.Get(headerGitHubDelivery)
	case config.VendorBitbucket:
		return header.Get(headerBitbucketEvent), header.Get(headerRequestID)
	case config.VendorAzureDevOps:
		// Azure DevOps service hooks carry no event header; the subscription is
		// per event type, and its request ID is the delivery identity.
		return azureDevOpsEventType, header.Get(headerRequestID)
	}
	return "", ""
}

// normalizeEventType maps GitLab's "Push Hook" onto the "push" the control
// plane matches on, leaving anything else lowercased and underscored.
func normalizeEventType(raw string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(raw), " Hook")
	return strings.ReplaceAll(strings.ToLower(trimmed), " ", "_")
}

// Serve runs the listener on addr until stop is called. The listener is opened
// synchronously so an unusable address fails startup instead of never serving.
func (l *Listener) Serve(addr string) (stop func(), err error) {
	srv := &http.Server{
		Addr:    addr,
		Handler: l.Handler(),
		// ReadTimeout, not just ReadHeaderTimeout: the handler buffers the body
		// before it verifies the signature, so without a whole-request deadline an
		// unauthenticated client holds a goroutine and an fd indefinitely by
		// dribbling one byte at a time — and the connector is the customer's only
		// tunnel process.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: --webhook-addr %s: %w", config.ErrInvalidConfig, addr, err)
	}
	go func() {
		if serveErr := srv.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			l.logger.Error("webhook listener stopped", "error", serveErr)
		}
	}()
	l.logger.Info("webhook listener listening", "addr", listener.Addr().String(), "path", Path)
	return func() { _ = srv.Close() }, nil
}
