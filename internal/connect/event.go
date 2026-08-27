// ABOUTME: Connector-originated event relay — the one exchange the connector initiates.
// ABOUTME: Sends an Event upstream and waits for the gateway's EventAck on the same request ID.
package connect

import (
	"context"
	"errors"
	"fmt"

	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// ErrNoTunnel means no live tunnel connection can carry an event right now. The
// caller answers the vendor with a retryable status so it redelivers.
var ErrNoTunnel = errors.New("connect: no live tunnel connection")

// SendEvent relays one event to the gateway and waits for its ack. The request
// ID is fresh per attempt; the event's delivery ID is what stays stable across
// retries, so the control plane can collapse a redelivery.
func (c *Conn) SendEvent(ctx context.Context, event *tunnel.Event) (*tunnel.EventAck, error) {
	requestID := fmt.Sprintf("evt.%d", c.eventSeq.Add(1))
	ack := make(chan *tunnel.EventAck, 1)

	c.eventsMu.Lock()
	if c.events == nil {
		c.events = make(map[string]chan *tunnel.EventAck)
	}
	c.events[requestID] = ack
	c.eventsMu.Unlock()
	defer func() {
		c.eventsMu.Lock()
		delete(c.events, requestID)
		c.eventsMu.Unlock()
	}()

	err := c.enqueue(&tunnel.Envelope{
		RequestId: requestID,
		Msg:       &tunnel.Envelope_Event{Event: event},
	})
	if err != nil {
		return nil, err
	}

	select {
	case got := <-ack:
		return got, nil
	case <-c.closed:
		return nil, ErrNoTunnel
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// deliverEventAck hands one ack to the waiting SendEvent. An ack for an event
// that already gave up is dropped: the vendor has been answered either way.
func (c *Conn) deliverEventAck(env *tunnel.Envelope) error {
	c.eventsMu.Lock()
	waiter := c.events[env.GetRequestId()]
	c.eventsMu.Unlock()
	if waiter == nil {
		return nil
	}
	select {
	case waiter <- env.GetEventAck():
	default:
		// A second ack for one event is a protocol violation, but dropping it is
		// enough — the exchange is already settled.
	}
	return nil
}
