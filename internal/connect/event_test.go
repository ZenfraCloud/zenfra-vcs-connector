// ABOUTME: Tests for the connector-originated event relay over a live tunnel connection.
// ABOUTME: Covers ack delivery, refusal, connection loss and the gateway-role guard.
package connect

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

func pushEvent() *tunnel.Event {
	return &tunnel.Event{
		Vendor:     "gitlab",
		EventType:  "push",
		DeliveryId: "delivery-1",
		Payload:    []byte(`{"object_kind":"push"}`),
	}
}

func TestSendEventWaitsForAck(t *testing.T) {
	g := newStubGateway(t, false)
	d := testDialer(func(context.Context, *Request, *Responder) {})
	conn, _ := dialStub(t, g, d, LaneInteractive)
	gw := g.next(t)

	acked := make(chan *tunnel.EventAck, 1)
	go func() {
		ack, err := conn.SendEvent(context.Background(), pushEvent())
		if err != nil {
			t.Errorf("SendEvent() error = %v", err)
			close(acked)
			return
		}
		acked <- ack
	}()

	got := recv(t, gw)
	event := got.GetEvent()
	if event == nil {
		t.Fatalf("gateway received %v, want an Event", got)
	}
	if event.GetDeliveryId() != "delivery-1" || event.GetEventType() != "push" {
		t.Errorf("event = %v", event)
	}
	if got.GetRequestId() == "" {
		t.Error("event must carry a request id so its ack can be correlated")
	}

	send(t, gw, &tunnel.Envelope{
		RequestId: got.GetRequestId(),
		Msg:       &tunnel.Envelope_EventAck{EventAck: &tunnel.EventAck{Accepted: true}},
	})

	select {
	case ack := <-acked:
		if ack == nil || !ack.GetAccepted() {
			t.Fatalf("ack = %v, want accepted", ack)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SendEvent never observed its ack")
	}
}

func TestSendEventReportsRefusal(t *testing.T) {
	g := newStubGateway(t, false)
	d := testDialer(func(context.Context, *Request, *Responder) {})
	conn, _ := dialStub(t, g, d, LaneInteractive)
	gw := g.next(t)

	done := make(chan *tunnel.EventAck, 1)
	go func() {
		ack, err := conn.SendEvent(context.Background(), pushEvent())
		if err != nil {
			t.Errorf("SendEvent() error = %v", err)
		}
		done <- ack
	}()

	got := recv(t, gw)
	send(t, gw, &tunnel.Envelope{
		RequestId: got.GetRequestId(),
		Msg: &tunnel.Envelope_EventAck{EventAck: &tunnel.EventAck{
			Code: tunnel.ErrCodePolicyDenied, Message: "no stack matches",
		}},
	})

	select {
	case ack := <-done:
		if ack.GetAccepted() {
			t.Fatal("a refused event must not report accepted")
		}
		if ack.GetCode() != tunnel.ErrCodePolicyDenied {
			t.Errorf("code = %q", ack.GetCode())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SendEvent never observed its ack")
	}
}

// A dead connection must fail the send rather than hang: the listener has a
// vendor waiting on the other end, and a retryable answer makes it redeliver.
func TestSendEventFailsWhenConnectionCloses(t *testing.T) {
	g := newStubGateway(t, false)
	d := testDialer(func(context.Context, *Request, *Responder) {})
	conn, _ := dialStub(t, g, d, LaneInteractive)
	g.next(t)

	errc := make(chan error, 1)
	go func() {
		_, err := conn.SendEvent(context.Background(), pushEvent())
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	conn.Close()

	select {
	case err := <-errc:
		if !errors.Is(err, ErrNoTunnel) {
			t.Fatalf("SendEvent() error = %v, want ErrNoTunnel", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SendEvent did not fail when the connection closed")
	}
}

// The gateway is never an event source. A connector that accepted one would be
// letting whatever it is talking to inject webhooks into its own network.
func TestGatewaySentEventEndsConnection(t *testing.T) {
	g := newStubGateway(t, false)
	d := testDialer(func(context.Context, *Request, *Responder) {})
	_, served := dialStub(t, g, d, LaneInteractive)
	gw := g.next(t)

	send(t, gw, &tunnel.Envelope{
		RequestId: "evt.1",
		Msg:       &tunnel.Envelope_Event{Event: pushEvent()},
	})

	select {
	case err := <-served:
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("Serve() error = %v, want ErrProtocol", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("connector accepted a gateway-sent event")
	}
}

// An ack for an event nobody is waiting on is late, not fatal.
func TestUnmatchedEventAckIsIgnored(t *testing.T) {
	g := newStubGateway(t, false)
	d := testDialer(func(context.Context, *Request, *Responder) {})
	_, served := dialStub(t, g, d, LaneInteractive)
	gw := g.next(t)

	send(t, gw, &tunnel.Envelope{
		RequestId: "evt.999",
		Msg:       &tunnel.Envelope_EventAck{EventAck: &tunnel.EventAck{Accepted: true}},
	})

	select {
	case err := <-served:
		t.Fatalf("connection ended on a late ack: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}
