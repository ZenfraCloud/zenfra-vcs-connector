// ABOUTME: Cancellation tests — the upstream call aborts and the ack states the true terminal state.
// ABOUTME: Also covers the transport-error to wire-code mapping used when no cancel is involved.
package executor

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// waitFor blocks until c fires, failing the test on timeout.
func waitFor(t *testing.T, c <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// A cancel that lands before the request leaves the connector is answered
// not_sent: the upstream never saw it, so it is safe to retry elsewhere.
func TestHandle_CancelBeforeDispatchReportsNotSent(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w := newFakeResponder()
	exec.Handle(ctx, req(http.MethodGet, "/api/v4/user", ""), w)

	got := w.snapshot()
	if got.ack == nil {
		t.Fatalf("no CancelAck (failure=%v)", got.failure)
	}
	if got.ack.GetOutcome() != tunnel.CancelOutcome_CANCEL_OUTCOME_NOT_SENT {
		t.Errorf("outcome = %v, want NOT_SENT", got.ack.GetOutcome())
	}
	if stub.count() != 0 {
		t.Errorf("cancelled request still reached upstream (%d hits)", stub.count())
	}
}

// A cancel while the request is in flight aborts the upstream call, and the ack
// admits the effect is unknowable — the write may or may not have landed.
func TestHandle_CancelInFlightAbortsUpstreamAndReportsUnknown(t *testing.T) {
	arrived := make(chan struct{})
	aborted := make(chan struct{})
	stub := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-r.Context().Done()
		close(aborted)
		w.WriteHeader(http.StatusOK)
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := newFakeResponder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		exec.Handle(ctx, withBody(
			req(http.MethodPost, "/api/v4/projects/1/merge_requests/2/notes", ""), `{"body":"hi"}`), w)
	}()

	waitFor(t, arrived, "the upstream request")
	cancel()
	waitFor(t, aborted, "the upstream call to abort")
	waitFor(t, done, "Handle to return")

	got := w.snapshot()
	if got.ack == nil {
		t.Fatalf("no CancelAck (failure=%v)", got.failure)
	}
	if got.ack.GetOutcome() != tunnel.CancelOutcome_CANCEL_OUTCOME_OUTCOME_UNKNOWN {
		t.Errorf("outcome = %v, want OUTCOME_UNKNOWN", got.ack.GetOutcome())
	}
	if got.headSent {
		t.Error("a cancelled request sent a response head")
	}
}

// Once the status line is back the side effect has already happened, so a cancel
// arriving mid-body is answered completed even though the body never finished.
func TestHandle_CancelAfterHeadReportsCompleted(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":`))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := newFakeResponder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		exec.Handle(ctx, withBody(
			req(http.MethodPost, "/api/v4/projects/1/merge_requests/2/notes", ""), `{"body":"hi"}`), w)
	}()

	waitFor(t, w.headCh, "the response head")
	cancel()
	waitFor(t, done, "Handle to return")

	got := w.snapshot()
	if got.ack == nil {
		t.Fatalf("no CancelAck (failure=%v)", got.failure)
	}
	if got.ack.GetOutcome() != tunnel.CancelOutcome_CANCEL_OUTCOME_COMPLETED {
		t.Errorf("outcome = %v, want COMPLETED", got.ack.GetOutcome())
	}
	if got.closed {
		t.Error("terminal chunk sent for a body that never finished")
	}
}

func TestCancelOutcome(t *testing.T) {
	for phase, want := range map[int]tunnel.CancelOutcome{
		phaseNotSent:   tunnel.CancelOutcome_CANCEL_OUTCOME_NOT_SENT,
		phaseInFlight:  tunnel.CancelOutcome_CANCEL_OUTCOME_OUTCOME_UNKNOWN,
		phaseCompleted: tunnel.CancelOutcome_CANCEL_OUTCOME_COMPLETED,
	} {
		if got := cancelOutcome(phase); got != want {
			t.Errorf("cancelOutcome(%d) = %v, want %v", phase, got, want)
		}
	}
}

func TestClassifyUpstreamError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"dns", &net.DNSError{Err: "no such host", Name: "gitlab.internal"}, tunnel.ErrCodeUpstreamDNS},
		{"tls", &tls.CertificateVerificationError{Err: errors.New("unknown authority")}, tunnel.ErrCodeUpstreamTLS},
		{"deadline", context.DeadlineExceeded, tunnel.ErrCodeUpstreamTimeout},
		{"conn", errors.New("connection refused"), tunnel.ErrCodeUpstreamConn},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, message := classifyUpstreamError(tc.err, context.Background())
			if code != tc.want {
				t.Errorf("code = %q, want %q", code, tc.want)
			}
			if message == "" {
				t.Error("message is empty")
			}
		})
	}
}
