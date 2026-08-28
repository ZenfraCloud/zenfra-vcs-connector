// ABOUTME: Tests for the control-plane registration and token-refresh client.
// ABOUTME: Covers the register→JWT flow, refresh, and retryable vs terminal failures.
package connect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientRegister(t *testing.T) {
	var gotAuth, gotPath, gotContentType string
	var gotBody map[string]string
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connector_id": "c1",
			"instance_id":  "i1",
			"token":        "jwt-1",
			"expires_at":   expires,
			"endpoint":     "https://gitlab.internal",
			"vendor":       "gitlab",
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, nil)
	inst, err := client.Register(context.Background(), "vcsc_abc.def", "connector-0", "1.2.3")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if want := "Bearer vcsc_abc.def"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
	if want := "/api/v1/vcs/connector/register"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if want := "application/json"; gotContentType != want {
		t.Errorf("Content-Type = %q, want %q", gotContentType, want)
	}
	if gotBody["instance_key"] != "connector-0" || gotBody["version"] != "1.2.3" {
		t.Errorf("body = %v, want instance_key/version", gotBody)
	}
	if inst.Token != "jwt-1" || inst.ConnectorID != "c1" || inst.InstanceID != "i1" {
		t.Errorf("instance = %+v", inst)
	}
	if !inst.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", inst.ExpiresAt, expires)
	}
	if inst.Endpoint != "https://gitlab.internal" || inst.Vendor != "gitlab" {
		t.Errorf("instance endpoint/vendor = %q/%q", inst.Endpoint, inst.Vendor)
	}
}

func TestClientRefresh(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connector_id": "c1",
			"instance_id":  "i1",
			"token":        "jwt-2",
			"expires_at":   time.Now().Add(time.Hour),
		})
	}))
	defer srv.Close()

	inst, err := NewClient(srv.URL, nil).Refresh(context.Background(), "jwt-1")
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if want := "Bearer jwt-1"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
	if want := "/api/v1/vcs/connector/refresh"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if inst.Token != "jwt-2" {
		t.Errorf("Token = %q, want the refreshed token", inst.Token)
	}
}

func TestClientErrorClassification(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		retryable bool
	}{
		{"unauthorized is terminal", http.StatusUnauthorized, false},
		{"forbidden is terminal", http.StatusForbidden, false},
		{"not found is terminal", http.StatusNotFound, false},
		{"rate limited is retryable", http.StatusTooManyRequests, true},
		{"server error is retryable", http.StatusInternalServerError, true},
		{"gateway unavailable is retryable", http.StatusServiceUnavailable, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "boom", "message": "detail from control plane",
				})
			}))
			defer srv.Close()

			_, err := NewClient(srv.URL, nil).Register(context.Background(), "vcsc_a.b", "k", "v")
			if err == nil {
				t.Fatal("Register() error = nil, want error")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error %v is not an *APIError", err)
			}
			if apiErr.Status != tt.status {
				t.Errorf("Status = %d, want %d", apiErr.Status, tt.status)
			}
			if apiErr.Retryable() != tt.retryable {
				t.Errorf("Retryable() = %v, want %v", apiErr.Retryable(), tt.retryable)
			}
			if apiErr.Message != "detail from control plane" {
				t.Errorf("Message = %q, want the control-plane detail", apiErr.Message)
			}
		})
	}
}

// IsRetryable decides whether the connector lives or dies: a "false" here ends
// the process for good, so every arm is pinned.
func TestIsRetryableClassification(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer slow.Close()
	// An http.Client timeout satisfies errors.Is(err, context.DeadlineExceeded),
	// so treating that sentinel as terminal would kill the connector whenever the
	// control plane is merely slow.
	_, clientTimeout := (&http.Client{Timeout: 10 * time.Millisecond}).Get(slow.URL)
	if clientTimeout == nil {
		t.Fatal("expected the client to time out")
	}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"cancelled context", context.Canceled, false},
		{"client timeout", clientTimeout, true},
		{"deadline exceeded", context.DeadlineExceeded, true},
		{"rejected credential", &APIError{Status: http.StatusUnauthorized}, false},
		{"forbidden", &APIError{Status: http.StatusForbidden}, false},
		{"rate limited", &APIError{Status: http.StatusTooManyRequests}, true},
		{"control plane down", &APIError{Status: http.StatusServiceUnavailable}, true},
		{"transport failure", errors.New("dial tcp: connection refused"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryable(tt.err); got != tt.want {
				t.Errorf("IsRetryable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestClientNetworkFailureIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // nothing is listening now

	_, err := NewClient(srv.URL, nil).Register(context.Background(), "vcsc_a.b", "k", "v")
	if err == nil {
		t.Fatal("Register() error = nil, want error")
	}
	if !IsRetryable(err) {
		t.Errorf("IsRetryable(%v) = false, want true for a dial failure", err)
	}
}

func TestClientMissingTokenIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"connector_id": "c1", "instance_id": "i1"})
	}))
	defer srv.Close()

	if _, err := NewClient(srv.URL, nil).Register(context.Background(), "vcsc_a.b", "k", "v"); err == nil {
		t.Fatal("Register() error = nil, want error for a response without a token")
	}
}

func TestClientRespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Never answers within the caller's deadline; the upper bound keeps
		// Close() from blocking if the client somehow succeeds.
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := NewClient(srv.URL, nil).Register(ctx, "vcsc_a.b", "k", "v"); err == nil {
		t.Fatal("Register() error = nil, want a context error")
	}
}
