// ABOUTME: Encode/decode helpers for tunnel envelopes — one envelope per binary WS frame.
// ABOUTME: Enforces chunk size/sequencing rules and request-ID immutability/uniqueness.
package tunnel

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
)

const (
	// MaxChunkBytes is the hard cap on BodyChunk data per the protocol spec (32–64 KiB).
	MaxChunkBytes = 64 * 1024
	// DefaultChunkBytes is the recommended chunk size for senders.
	DefaultChunkBytes = 32 * 1024
	// MaxEventBytes caps an Event payload. Vendors bound their own webhook
	// bodies well below this (GitLab ships at most 20 commits per push), and an
	// Event is a single frame — it has no chunked form to grow into.
	MaxEventBytes = 64 * 1024
)

// HeaderPolicyRule carries the connector allowlist rule that authorized a request
// back on its response head, so the gateway's audit record can name the rule.
const HeaderPolicyRule = "X-Zenfra-Policy-Rule"

// Stable wire error codes carried in Error.code. Renaming one breaks deployed
// connectors — treat as append-only.
const (
	ErrCodeAuth                     = "auth"
	ErrCodePolicyDenied             = "policy_denied"
	ErrCodeConnectorOffline         = "connector_offline"
	ErrCodeConnectorBusy            = "connector_busy"
	ErrCodeStreamLostBeforeDispatch = "stream_lost_before_dispatch"
	ErrCodeOutcomeUnknown           = "outcome_unknown"
	ErrCodeUpstreamDNS              = "upstream_dns"
	ErrCodeUpstreamTLS              = "upstream_tls"
	ErrCodeUpstreamConn             = "upstream_conn"
	ErrCodeUpstreamTimeout          = "upstream_timeout"
	ErrCodeUpstreamHTTP             = "upstream_http"
	ErrCodeTooLarge                 = "too_large"
	ErrCodeProtocol                 = "protocol"
	ErrCodeCancelled                = "cancelled"
)

var (
	ErrEmptyRequestID     = errors.New("tunnel: empty request id")
	ErrNoMessage          = errors.New("tunnel: envelope has no message")
	ErrChunkTooLarge      = fmt.Errorf("tunnel: chunk exceeds %d bytes", MaxChunkBytes)
	ErrDuplicateChunk     = errors.New("tunnel: duplicate or out-of-order chunk")
	ErrChunkGap           = errors.New("tunnel: gap in chunk sequence")
	ErrChunkAfterTerminal = errors.New("tunnel: chunk after terminal marker")
	ErrRequestIDMismatch  = errors.New("tunnel: request id changed mid-exchange")
	ErrDuplicateRequestID = errors.New("tunnel: duplicate request id")
	ErrEventTooLarge      = fmt.Errorf("tunnel: event payload exceeds %d bytes", MaxEventBytes)
	ErrEventIncomplete    = errors.New("tunnel: event missing vendor, event type or delivery id")
)

func validate(env *Envelope) error {
	if env == nil || env.GetMsg() == nil {
		return ErrNoMessage
	}
	if env.GetRequestId() == "" {
		return ErrEmptyRequestID
	}
	if chunk := env.GetBodyChunk(); chunk != nil && len(chunk.GetData()) > MaxChunkBytes {
		return fmt.Errorf("%w: got %d", ErrChunkTooLarge, len(chunk.GetData()))
	}
	if event := env.GetEvent(); event != nil {
		return validateEvent(event)
	}
	return nil
}

// validateEvent rejects an event the receiver could not route or dedupe. Both
// checks are on the wire so a malformed relay dies at the frame rather than
// halfway through run creation.
func validateEvent(event *Event) error {
	if event.GetVendor() == "" || event.GetEventType() == "" || event.GetDeliveryId() == "" {
		return ErrEventIncomplete
	}
	if len(event.GetPayload()) > MaxEventBytes {
		return fmt.Errorf("%w: got %d", ErrEventTooLarge, len(event.GetPayload()))
	}
	return nil
}

// Encode validates env and marshals it into the payload of one binary WS frame.
func Encode(env *Envelope) ([]byte, error) {
	if err := validate(env); err != nil {
		return nil, err
	}
	return proto.Marshal(env)
}

// Decode unmarshals the payload of one binary WS frame and validates it.
func Decode(b []byte) (*Envelope, error) {
	env := &Envelope{}
	if err := proto.Unmarshal(b, env); err != nil {
		return nil, fmt.Errorf("tunnel: unmarshal: %w", err)
	}
	if err := validate(env); err != nil {
		return nil, err
	}
	return env, nil
}

// ChunkSequencer validates the BodyChunk stream of one exchange: fixed request
// ID, sequence starting at 0 incrementing by 1, nothing after terminal.
type ChunkSequencer struct {
	requestID string
	next      uint64
	terminal  bool
}

func NewChunkSequencer(requestID string) *ChunkSequencer {
	return &ChunkSequencer{requestID: requestID}
}

// Terminal reports whether the terminal chunk has been accepted.
func (s *ChunkSequencer) Terminal() bool { return s.terminal }

// Accept validates the next chunk envelope in the stream.
func (s *ChunkSequencer) Accept(env *Envelope) error {
	if err := validate(env); err != nil {
		return err
	}
	if env.GetRequestId() != s.requestID {
		return fmt.Errorf("%w: got %q want %q", ErrRequestIDMismatch, env.GetRequestId(), s.requestID)
	}
	chunk := env.GetBodyChunk()
	if chunk == nil {
		return fmt.Errorf("%w: expected body chunk", ErrNoMessage)
	}
	if s.terminal {
		return fmt.Errorf("%w: sequence %d", ErrChunkAfterTerminal, chunk.GetSequence())
	}
	switch seq := chunk.GetSequence(); {
	case seq < s.next:
		return fmt.Errorf("%w: sequence %d already consumed", ErrDuplicateChunk, seq)
	case seq > s.next:
		return fmt.Errorf("%w: got %d want %d", ErrChunkGap, seq, s.next)
	}
	s.next++
	s.terminal = chunk.GetTerminal()
	return nil
}
