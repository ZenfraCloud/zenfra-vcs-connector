// ABOUTME: Tests for the connector binary's wiring: misconfiguration is terminal, a valid
// ABOUTME: config reaches the control plane, and a cancelled context is a clean stop.
package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
)

func noEnv(string) string { return "" }

func TestRunRejectsMisconfiguration(t *testing.T) {
	err := run(context.Background(), []string{"--gateway-url", "http://gw"}, noEnv)
	if !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestRunRejectsUnbuildablePolicyScope(t *testing.T) {
	// Neither --allowed-projects nor --all-projects: terminal, not a retry loop.
	err := run(context.Background(), []string{
		"--gateway-url", "http://gw", "--bootstrap-token", "vcsc_x.y",
		"--endpoint", "https://gitlab.internal", "--vendor", "gitlab",
		"--secret-file", "/dev/null",
	}, noEnv)
	if !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestRunRegistersThenStopsOnContextCancel(t *testing.T) {
	var registrations atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/vcs/connector/register" {
			// The tunnel upgrade: answer retryably so the manager keeps trying
			// and a cancelled context is what actually stops it.
			http.Error(w, "gateway unavailable", http.StatusServiceUnavailable)
			return
		}
		registrations.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// A registration that never yields a usable tunnel: the manager keeps
		// retrying the dial, which is exactly what a stop must interrupt.
		_, _ = w.Write([]byte(`{"connector_id":"c","instance_id":"i","token":"t",` +
			`"expires_at":"2999-01-01T00:00:00Z","endpoint":"https://gitlab.internal","vendor":"gitlab"}`))
	}))
	defer gateway.Close()

	secret := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(secret, []byte("glpat-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{
			"--gateway-url", gateway.URL,
			"--bootstrap-token", "vcsc_key.secret",
			"--endpoint", "https://gitlab.internal",
			"--vendor", "gitlab",
			"--secret-file", secret,
			"--all-projects",
			"--instance-key", "test-instance",
			"--interactive-connections", "1",
		}, noEnv)
	}()

	deadline := time.After(10 * time.Second)
	for registrations.Load() == 0 {
		select {
		case err := <-done:
			t.Fatalf("run returned before registering: %v", err)
		case <-deadline:
			t.Fatal("connector never registered")
		case <-time.After(20 * time.Millisecond):
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancelled run should stop cleanly, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop after context cancel")
	}
}
