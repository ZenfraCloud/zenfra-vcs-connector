// ABOUTME: Tests for tunnel envelope encode/decode round-trips and validation.
// ABOUTME: Covers chunk-sequencing violations and request-ID immutability/uniqueness.
package tunnel

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
)

func mustEncode(t *testing.T, env *Envelope) []byte {
	t.Helper()
	b, err := Encode(env)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

func roundTrip(t *testing.T, env *Envelope) *Envelope {
	t.Helper()
	got, err := Decode(mustEncode(t, env))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !proto.Equal(env, got) {
		t.Fatalf("round-trip mismatch:\nsent: %v\ngot:  %v", env, got)
	}
	return got
}

func TestRoundTripHTTPRequest(t *testing.T) {
	env := &Envelope{
		RequestId: "req-1",
		Msg: &Envelope_HttpRequest{HttpRequest: &HTTPRequest{
			Method: "GET",
			Path:   "/api/v4/projects/42/repository/commits",
			Query:  "ref_name=main&per_page=50",
			Headers: map[string]*HeaderValues{
				"Accept": {Values: []string{"application/json"}},
			},
			DeadlineClass: DeadlineClass_DEADLINE_CLASS_INTERACTIVE,
			HasBody:       false,
		}},
	}
	got := roundTrip(t, env)
	req := got.GetHttpRequest()
	if req == nil {
		t.Fatal("decoded envelope is not an HTTPRequest")
	}
	if req.GetDeadlineClass() != DeadlineClass_DEADLINE_CLASS_INTERACTIVE {
		t.Errorf("deadline class = %v", req.GetDeadlineClass())
	}
	if req.GetQuery() != "ref_name=main&per_page=50" {
		t.Errorf("query = %q", req.GetQuery())
	}
}

func TestRoundTripHTTPResponseHead(t *testing.T) {
	env := &Envelope{
		RequestId: "req-2",
		Msg: &Envelope_HttpResponseHead{HttpResponseHead: &HTTPResponseHead{
			Status: 200,
			Headers: map[string]*HeaderValues{
				"Content-Type": {Values: []string{"application/json"}},
				"X-Multi":      {Values: []string{"a", "b"}},
			},
			HasBody: true,
		}},
	}
	got := roundTrip(t, env)
	head := got.GetHttpResponseHead()
	if head == nil || head.GetStatus() != 200 || !head.GetHasBody() {
		t.Fatalf("decoded head = %v", head)
	}
	if vals := head.GetHeaders()["X-Multi"].GetValues(); len(vals) != 2 {
		t.Errorf("multi-value header lost: %v", vals)
	}
}

func TestRoundTripBodyChunk(t *testing.T) {
	data := bytes.Repeat([]byte{0xAB}, MaxChunkBytes)
	env := &Envelope{
		RequestId: "req-3",
		Msg: &Envelope_BodyChunk{BodyChunk: &BodyChunk{
			Sequence: 7,
			Data:     data,
			Terminal: true,
		}},
	}
	got := roundTrip(t, env)
	chunk := got.GetBodyChunk()
	if chunk.GetSequence() != 7 || !chunk.GetTerminal() || !bytes.Equal(chunk.GetData(), data) {
		t.Fatalf("decoded chunk = seq %d terminal %v len %d",
			chunk.GetSequence(), chunk.GetTerminal(), len(chunk.GetData()))
	}
}

func TestRoundTripCancelAndAck(t *testing.T) {
	roundTrip(t, &Envelope{RequestId: "req-4", Msg: &Envelope_Cancel{Cancel: &Cancel{}}})
	for _, outcome := range []CancelOutcome{
		CancelOutcome_CANCEL_OUTCOME_NOT_SENT,
		CancelOutcome_CANCEL_OUTCOME_COMPLETED,
		CancelOutcome_CANCEL_OUTCOME_OUTCOME_UNKNOWN,
	} {
		got := roundTrip(t, &Envelope{
			RequestId: "req-4",
			Msg:       &Envelope_CancelAck{CancelAck: &CancelAck{Outcome: outcome}},
		})
		if got.GetCancelAck().GetOutcome() != outcome {
			t.Errorf("outcome = %v, want %v", got.GetCancelAck().GetOutcome(), outcome)
		}
	}
}

func TestRoundTripError(t *testing.T) {
	env := &Envelope{
		RequestId: "req-5",
		Msg: &Envelope_Error{Error: &Error{
			Code:      ErrCodePolicyDenied,
			Message:   "path not allowlisted",
			Retryable: false,
			Origin:    ErrorOrigin_ERROR_ORIGIN_CONNECTOR,
		}},
	}
	got := roundTrip(t, env)
	e := got.GetError()
	if e.GetCode() != ErrCodePolicyDenied || e.GetRetryable() ||
		e.GetOrigin() != ErrorOrigin_ERROR_ORIGIN_CONNECTOR {
		t.Fatalf("decoded error = %v", e)
	}
}

func TestEncodeRejectsInvalidEnvelopes(t *testing.T) {
	cases := []struct {
		name    string
		env     *Envelope
		wantErr error
	}{
		{"nil envelope", nil, ErrNoMessage},
		{"empty request id", &Envelope{Msg: &Envelope_Cancel{Cancel: &Cancel{}}}, ErrEmptyRequestID},
		{"no message set", &Envelope{RequestId: "x"}, ErrNoMessage},
		{"oversize chunk", &Envelope{
			RequestId: "x",
			Msg: &Envelope_BodyChunk{BodyChunk: &BodyChunk{
				Data: make([]byte, MaxChunkBytes+1),
			}},
		}, ErrChunkTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Encode(tc.env); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Encode err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDecodeRejectsInvalidPayloads(t *testing.T) {
	if _, err := Decode([]byte{0xFF, 0xFF, 0xFF, 0xFF}); err == nil {
		t.Fatal("Decode accepted garbage bytes")
	}
	// A structurally valid proto that fails envelope validation: no request ID.
	raw, err := proto.Marshal(&Envelope{Msg: &Envelope_Cancel{Cancel: &Cancel{}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(raw); !errors.Is(err, ErrEmptyRequestID) {
		t.Fatalf("Decode err = %v, want %v", err, ErrEmptyRequestID)
	}
	// Oversize chunk rejected on decode too, not just encode.
	raw, err = proto.Marshal(&Envelope{
		RequestId: "x",
		Msg: &Envelope_BodyChunk{BodyChunk: &BodyChunk{
			Data: make([]byte, MaxChunkBytes+1),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(raw); !errors.Is(err, ErrChunkTooLarge) {
		t.Fatalf("Decode err = %v, want %v", err, ErrChunkTooLarge)
	}
}

func chunkEnv(requestID string, seq uint64, size int, terminal bool) *Envelope {
	return &Envelope{
		RequestId: requestID,
		Msg: &Envelope_BodyChunk{BodyChunk: &BodyChunk{
			Sequence: seq,
			Data:     make([]byte, size),
			Terminal: terminal,
		}},
	}
}

func TestChunkSequencerAcceptsOrderedChunks(t *testing.T) {
	s := NewChunkSequencer("req-1")
	for seq := uint64(0); seq < 3; seq++ {
		if err := s.Accept(chunkEnv("req-1", seq, 10, seq == 2)); err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
	}
	if !s.Terminal() {
		t.Fatal("sequencer not terminal after terminal chunk")
	}
}

func TestChunkSequencerViolations(t *testing.T) {
	t.Run("duplicate", func(t *testing.T) {
		s := NewChunkSequencer("r")
		_ = s.Accept(chunkEnv("r", 0, 1, false))
		if err := s.Accept(chunkEnv("r", 0, 1, false)); !errors.Is(err, ErrDuplicateChunk) {
			t.Fatalf("err = %v, want %v", err, ErrDuplicateChunk)
		}
	})
	t.Run("gap", func(t *testing.T) {
		s := NewChunkSequencer("r")
		_ = s.Accept(chunkEnv("r", 0, 1, false))
		if err := s.Accept(chunkEnv("r", 2, 1, false)); !errors.Is(err, ErrChunkGap) {
			t.Fatalf("err = %v, want %v", err, ErrChunkGap)
		}
	})
	t.Run("out of order", func(t *testing.T) {
		// Swapped delivery 0,2,1: the first deviation (2) is a gap; the
		// late chunk (1) is then a duplicate of an already-consumed slot.
		s := NewChunkSequencer("r")
		_ = s.Accept(chunkEnv("r", 0, 1, false))
		if err := s.Accept(chunkEnv("r", 2, 1, false)); !errors.Is(err, ErrChunkGap) {
			t.Fatalf("gap err = %v", err)
		}
		s2 := NewChunkSequencer("r")
		_ = s2.Accept(chunkEnv("r", 0, 1, false))
		_ = s2.Accept(chunkEnv("r", 1, 1, false))
		if err := s2.Accept(chunkEnv("r", 0, 1, false)); !errors.Is(err, ErrDuplicateChunk) {
			t.Fatalf("late err = %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		s := NewChunkSequencer("r")
		if err := s.Accept(chunkEnv("r", 0, MaxChunkBytes+1, false)); !errors.Is(err, ErrChunkTooLarge) {
			t.Fatalf("err = %v, want %v", err, ErrChunkTooLarge)
		}
	})
	t.Run("after terminal", func(t *testing.T) {
		s := NewChunkSequencer("r")
		_ = s.Accept(chunkEnv("r", 0, 1, true))
		if err := s.Accept(chunkEnv("r", 1, 1, false)); !errors.Is(err, ErrChunkAfterTerminal) {
			t.Fatalf("err = %v, want %v", err, ErrChunkAfterTerminal)
		}
	})
	t.Run("request id mismatch", func(t *testing.T) {
		s := NewChunkSequencer("r")
		if err := s.Accept(chunkEnv("other", 0, 1, false)); !errors.Is(err, ErrRequestIDMismatch) {
			t.Fatalf("err = %v, want %v", err, ErrRequestIDMismatch)
		}
	})
	t.Run("not a chunk", func(t *testing.T) {
		s := NewChunkSequencer("r")
		env := &Envelope{RequestId: "r", Msg: &Envelope_Cancel{Cancel: &Cancel{}}}
		if err := s.Accept(env); !errors.Is(err, ErrNoMessage) {
			t.Fatalf("err = %v, want %v", err, ErrNoMessage)
		}
	})
}

func TestRequestIDRegistry(t *testing.T) {
	r := NewRequestIDRegistry()
	if err := r.Claim("req-1"); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := r.Claim("req-1"); !errors.Is(err, ErrDuplicateRequestID) {
		t.Fatalf("duplicate claim err = %v, want %v", err, ErrDuplicateRequestID)
	}
	if err := r.Claim(""); !errors.Is(err, ErrEmptyRequestID) {
		t.Fatalf("empty claim err = %v, want %v", err, ErrEmptyRequestID)
	}
	r.Release("req-1")
	if err := r.Claim("req-1"); err != nil {
		t.Fatalf("claim after release: %v", err)
	}
}

func TestErrorCodesAreStable(t *testing.T) {
	// These codes are wire contract — renaming one breaks deployed connectors.
	want := map[string]string{
		ErrCodeAuth:                     "auth",
		ErrCodePolicyDenied:             "policy_denied",
		ErrCodeConnectorOffline:         "connector_offline",
		ErrCodeConnectorBusy:            "connector_busy",
		ErrCodeStreamLostBeforeDispatch: "stream_lost_before_dispatch",
		ErrCodeOutcomeUnknown:           "outcome_unknown",
		ErrCodeUpstreamDNS:              "upstream_dns",
		ErrCodeUpstreamTLS:              "upstream_tls",
		ErrCodeUpstreamConn:             "upstream_conn",
		ErrCodeUpstreamTimeout:          "upstream_timeout",
		ErrCodeUpstreamHTTP:             "upstream_http",
		ErrCodeTooLarge:                 "too_large",
		ErrCodeProtocol:                 "protocol",
		ErrCodeCancelled:                "cancelled",
	}
	for got, expected := range want {
		if got != expected {
			t.Errorf("error code %q, want %q", got, expected)
		}
	}
}

func TestRoundTripEvent(t *testing.T) {
	env := &Envelope{
		RequestId: "evt-1",
		Msg: &Envelope_Event{Event: &Event{
			Vendor:     "gitlab",
			EventType:  "push",
			DeliveryId: "5f9c1c8a-0000-4000-8000-000000000001",
			Payload:    []byte(`{"object_kind":"push"}`),
		}},
	}
	got := roundTrip(t, env)
	event := got.GetEvent()
	if event == nil {
		t.Fatal("decoded envelope is not an Event")
	}
	if event.GetDeliveryId() != "5f9c1c8a-0000-4000-8000-000000000001" {
		t.Errorf("delivery id = %q", event.GetDeliveryId())
	}
	if !bytes.Equal(event.GetPayload(), []byte(`{"object_kind":"push"}`)) {
		t.Errorf("payload = %q", event.GetPayload())
	}
}

func TestRoundTripEventAck(t *testing.T) {
	roundTrip(t, &Envelope{
		RequestId: "evt-1",
		Msg:       &Envelope_EventAck{EventAck: &EventAck{Accepted: true}},
	})
	got := roundTrip(t, &Envelope{
		RequestId: "evt-2",
		Msg: &Envelope_EventAck{EventAck: &EventAck{
			Code: ErrCodePolicyDenied, Message: "no stack matches",
		}},
	})
	if got.GetEventAck().GetAccepted() {
		t.Error("a refused ack must not report accepted")
	}
}

// A redelivered webhook keeps its delivery id under a fresh request id: the ack
// correlates the attempt, the delivery id makes the relay replay-safe.
func TestEventRetryKeepsDeliveryID(t *testing.T) {
	const deliveryID = "delivery-42"
	first := &Envelope{
		RequestId: "evt-1",
		Msg: &Envelope_Event{Event: &Event{
			Vendor: "gitlab", EventType: "push", DeliveryId: deliveryID,
			Payload: []byte(`{}`),
		}},
	}
	retry := &Envelope{
		RequestId: "evt-2",
		Msg: &Envelope_Event{Event: &Event{
			Vendor: "gitlab", EventType: "push", DeliveryId: deliveryID,
			Payload: []byte(`{}`),
		}},
	}
	if roundTrip(t, first).GetEvent().GetDeliveryId() != roundTrip(t, retry).GetEvent().GetDeliveryId() {
		t.Fatal("a retried event must carry the same delivery id")
	}
	if first.GetRequestId() == retry.GetRequestId() {
		t.Fatal("a retried event must carry a fresh request id")
	}
}

func TestEncodeRejectsIncompleteEvent(t *testing.T) {
	for name, event := range map[string]*Event{
		"no vendor":      {EventType: "push", DeliveryId: "d1"},
		"no event type":  {Vendor: "gitlab", DeliveryId: "d1"},
		"no delivery id": {Vendor: "gitlab", EventType: "push"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Encode(&Envelope{RequestId: "evt-1", Msg: &Envelope_Event{Event: event}})
			if !errors.Is(err, ErrEventIncomplete) {
				t.Fatalf("Encode error = %v, want ErrEventIncomplete", err)
			}
		})
	}
}

func TestEncodeRejectsOversizedEvent(t *testing.T) {
	_, err := Encode(&Envelope{
		RequestId: "evt-1",
		Msg: &Envelope_Event{Event: &Event{
			Vendor: "gitlab", EventType: "push", DeliveryId: "d1",
			Payload: make([]byte, MaxEventBytes+1),
		}},
	})
	if !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("Encode error = %v, want ErrEventTooLarge", err)
	}
}

// An oversized event must die at Decode too: a peer that skipped Encode's
// validation cannot smuggle one past the receiver.
func TestDecodeRejectsOversizedEvent(t *testing.T) {
	raw, err := proto.Marshal(&Envelope{
		RequestId: "evt-1",
		Msg: &Envelope_Event{Event: &Event{
			Vendor: "gitlab", EventType: "push", DeliveryId: "d1",
			Payload: make([]byte, MaxEventBytes+1),
		}},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := Decode(raw); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("Decode error = %v, want ErrEventTooLarge", err)
	}
}
