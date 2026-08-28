// ABOUTME: Tests for the connector's local webhook listener: secret verification and relay.
// ABOUTME: A stub relay stands in for the tunnel so every status code is asserted directly.

package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

const testSecret = "webhook-secret"

// stubRelay records what the listener sent and answers with a canned ack.
type stubRelay struct {
	events []*tunnel.Event
	ack    *tunnel.EventAck
	err    error
}

func (s *stubRelay) SendEvent(_ context.Context, event *tunnel.Event) (*tunnel.EventAck, error) {
	s.events = append(s.events, event)
	if s.err != nil {
		return nil, s.err
	}
	return s.ack, nil
}

func testListener(t *testing.T, vendor config.Vendor, relay Relay) *Listener {
	t.Helper()
	l, err := NewListener(vendor, testSecret, relay, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewListener() error = %v", err)
	}
	return l
}

func gitlabPush(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
	r.Header.Set(headerGitLabToken, testSecret)
	r.Header.Set(headerGitLabEvent, "Push Hook")
	r.Header.Set(headerGitLabDelivery, "delivery-1")
	return r
}

func TestAcceptedDeliveryIsRelayed(t *testing.T) {
	relay := &stubRelay{ack: &tunnel.EventAck{Accepted: true}}
	l := testListener(t, config.VendorGitLab, relay)

	rec := httptest.NewRecorder()
	l.Handler().ServeHTTP(rec, gitlabPush(`{"object_kind":"push"}`))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	if len(relay.events) != 1 {
		t.Fatalf("relayed %d events, want 1", len(relay.events))
	}
	event := relay.events[0]
	if event.GetVendor() != "gitlab" || event.GetEventType() != "push" {
		t.Errorf("event = %v, want vendor gitlab / type push", event)
	}
	if event.GetDeliveryId() != "delivery-1" {
		t.Errorf("delivery id = %q", event.GetDeliveryId())
	}
	if string(event.GetPayload()) != `{"object_kind":"push"}` {
		t.Errorf("payload = %q, want the body verbatim", event.GetPayload())
	}
}

// A redelivery keeps its delivery ID, which is what lets the control plane
// collapse it into the run the first one created.
func TestRedeliveryKeepsDeliveryID(t *testing.T) {
	relay := &stubRelay{ack: &tunnel.EventAck{Accepted: true}}
	l := testListener(t, config.VendorGitLab, relay)

	for range 2 {
		rec := httptest.NewRecorder()
		l.Handler().ServeHTTP(rec, gitlabPush(`{"object_kind":"push"}`))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", rec.Code)
		}
	}
	if len(relay.events) != 2 {
		t.Fatalf("relayed %d events, want 2", len(relay.events))
	}
	if relay.events[0].GetDeliveryId() != relay.events[1].GetDeliveryId() {
		t.Fatal("a redelivery must carry the same delivery id")
	}
}

func TestWrongSecretIsRejectedWithoutRelaying(t *testing.T) {
	relay := &stubRelay{ack: &tunnel.EventAck{Accepted: true}}
	l := testListener(t, config.VendorGitLab, relay)

	r := gitlabPush(`{"object_kind":"push"}`)
	r.Header.Set(headerGitLabToken, "not-the-secret")
	rec := httptest.NewRecorder()
	l.Handler().ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if len(relay.events) != 0 {
		t.Fatal("an unverified delivery must never reach the tunnel")
	}
}

func TestMissingSecretIsRejected(t *testing.T) {
	relay := &stubRelay{ack: &tunnel.EventAck{Accepted: true}}
	l := testListener(t, config.VendorGitLab, relay)

	r := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(`{}`))
	r.Header.Set(headerGitLabEvent, "Push Hook")
	r.Header.Set(headerGitLabDelivery, "delivery-1")
	rec := httptest.NewRecorder()
	l.Handler().ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestHMACSignatureIsVerified(t *testing.T) {
	relay := &stubRelay{ack: &tunnel.EventAck{Accepted: true}}
	l := testListener(t, config.VendorGitHub, relay)

	body := `{"ref":"refs/heads/main"}`
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(body))

	r := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
	r.Header.Set(headerHubSignature256, hmacSignaturePrefix+hex.EncodeToString(mac.Sum(nil)))
	r.Header.Set(headerGitHubEvent, "push")
	r.Header.Set(headerGitHubDelivery, "gh-delivery-1")
	rec := httptest.NewRecorder()
	l.Handler().ServeHTTP(rec, r)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
}

// Bitbucket Data Center signs on X-Hub-Signature, not GitHub's -256 variant, and
// Azure DevOps service hooks carry no signature at all — they authenticate with
// HTTP Basic. Verifying only GitHub's shape would 401 every delivery from both.
func TestVendorSpecificVerification(t *testing.T) {
	body := `{"eventKey":"repo:refs_changed"}`
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(body))
	signature := hmacSignaturePrefix + hex.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name     string
		vendor   config.Vendor
		headers  map[string]string
		wantCode int
	}{
		{
			name:   "bitbucket signature is accepted",
			vendor: config.VendorBitbucket,
			headers: map[string]string{
				headerHubSignature:   signature,
				headerBitbucketEvent: "repo:refs_changed",
				headerRequestID:      "bb-delivery-1",
			},
			wantCode: http.StatusAccepted,
		},
		{
			name:   "bitbucket rejects a bad signature",
			vendor: config.VendorBitbucket,
			headers: map[string]string{
				headerHubSignature:   hmacSignaturePrefix + "00",
				headerBitbucketEvent: "repo:refs_changed",
				headerRequestID:      "bb-delivery-2",
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "azure devops basic auth is accepted",
			vendor:   config.VendorAzureDevOps,
			headers:  map[string]string{"Authorization": basicAuth("zenfra", testSecret), headerRequestID: "ado-1"},
			wantCode: http.StatusAccepted,
		},
		{
			name:     "azure devops rejects a wrong password",
			vendor:   config.VendorAzureDevOps,
			headers:  map[string]string{"Authorization": basicAuth("zenfra", "nope"), headerRequestID: "ado-2"},
			wantCode: http.StatusUnauthorized,
		},
		{
			// A signed vendor must not be downgradable to the weaker verbatim
			// token comparison by omitting its signature.
			name:     "bitbucket rejects a gitlab-style token",
			vendor:   config.VendorBitbucket,
			headers:  map[string]string{headerGitLabToken: testSecret, headerRequestID: "bb-3"},
			wantCode: http.StatusUnauthorized,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := testListener(t, tc.vendor, &stubRelay{ack: &tunnel.EventAck{Accepted: true}})
			r := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
			for name, value := range tc.headers {
				r.Header.Set(name, value)
			}
			rec := httptest.NewRecorder()
			l.Handler().ServeHTTP(rec, r)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantCode)
			}
		})
	}
}

func basicAuth(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// A signature computed over a different body must not pass: that is the whole
// point of signing the payload rather than sending a bare token.
func TestTamperedBodyFailsHMAC(t *testing.T) {
	relay := &stubRelay{ack: &tunnel.EventAck{Accepted: true}}
	l := testListener(t, config.VendorGitHub, relay)

	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(`{"ref":"refs/heads/main"}`))

	r := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(`{"ref":"refs/heads/evil"}`))
	r.Header.Set(headerHubSignature256, hmacSignaturePrefix+hex.EncodeToString(mac.Sum(nil)))
	r.Header.Set(headerGitHubEvent, "push")
	r.Header.Set(headerGitHubDelivery, "gh-delivery-1")
	rec := httptest.NewRecorder()
	l.Handler().ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if len(relay.events) != 0 {
		t.Fatal("a tampered delivery must never reach the tunnel")
	}
}

// The tunnel being down must make the vendor redeliver, not lose the push.
func TestRelayFailureAsksForRedelivery(t *testing.T) {
	relay := &stubRelay{err: errors.New("no live tunnel connection")}
	l := testListener(t, config.VendorGitLab, relay)

	rec := httptest.NewRecorder()
	l.Handler().ServeHTTP(rec, gitlabPush(`{"object_kind":"push"}`))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// A refusal is the control plane's final answer; asking for a redelivery would
// just replay a rejection.
func TestRefusedEventIsNotRetried(t *testing.T) {
	relay := &stubRelay{ack: &tunnel.EventAck{Code: tunnel.ErrCodePolicyDenied}}
	l := testListener(t, config.VendorGitLab, relay)

	rec := httptest.NewRecorder()
	l.Handler().ServeHTTP(rec, gitlabPush(`{"object_kind":"push"}`))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestDeliveryWithoutIdentityIsRejected(t *testing.T) {
	relay := &stubRelay{ack: &tunnel.EventAck{Accepted: true}}
	l := testListener(t, config.VendorGitLab, relay)

	r := gitlabPush(`{}`)
	r.Header.Del(headerGitLabDelivery)
	rec := httptest.NewRecorder()
	l.Handler().ServeHTTP(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if len(relay.events) != 0 {
		t.Fatal("an unidentifiable delivery must never reach the tunnel")
	}
}

func TestOversizedPayloadIsRejected(t *testing.T) {
	relay := &stubRelay{ack: &tunnel.EventAck{Accepted: true}}
	l := testListener(t, config.VendorGitLab, relay)

	rec := httptest.NewRecorder()
	l.Handler().ServeHTTP(rec, gitlabPush(strings.Repeat("a", tunnel.MaxEventBytes+1)))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if len(relay.events) != 0 {
		t.Fatal("an oversized delivery must never reach the tunnel")
	}
}

func TestGetIsNotAWebhook(t *testing.T) {
	l := testListener(t, config.VendorGitLab, &stubRelay{ack: &tunnel.EventAck{Accepted: true}})

	rec := httptest.NewRecorder()
	l.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Path, http.NoBody))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestNewListenerRequiresASecret(t *testing.T) {
	if _, err := NewListener(config.VendorGitLab, "  ", &stubRelay{}, nil); err == nil {
		t.Fatal("NewListener accepted an empty secret")
	}
}

func TestNormalizeEventType(t *testing.T) {
	for raw, want := range map[string]string{
		"Push Hook":          "push",
		"Merge Request Hook": "merge_request",
		"push":               "push",
	} {
		if got := normalizeEventType(raw); got != want {
			t.Errorf("normalizeEventType(%q) = %q, want %q", raw, got, want)
		}
	}
}

// connector_busy and protocol are the gateway's transient refusals — the vendor
// has to redeliver, or the push is lost and the run never happens.
func TestTransientRefusalAsksForRedelivery(t *testing.T) {
	for _, code := range []string{tunnel.ErrCodeConnectorBusy, tunnel.ErrCodeProtocol} {
		t.Run(code, func(t *testing.T) {
			relay := &stubRelay{ack: &tunnel.EventAck{Code: code}}
			l := testListener(t, config.VendorGitLab, relay)

			rec := httptest.NewRecorder()
			l.Handler().ServeHTTP(rec, gitlabPush(`{"object_kind":"push"}`))

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", rec.Code)
			}
		})
	}
}
