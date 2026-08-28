// ABOUTME: Tests for the connector binary's wiring: misconfiguration is terminal, a valid
// ABOUTME: config reaches the control plane, and a cancelled context is a clean stop.
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/metrics"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/webhook"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
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

// A secret file the connector cannot read is "fix your flags", not "retry": left
// unchecked the process would register, open every stream and report healthy
// while every tunneled request failed on the credential.
func TestRunRejectsUnreadableSecretFile(t *testing.T) {
	err := run(context.Background(), []string{
		"--gateway-url", "http://gw", "--bootstrap-token", "vcsc_x.y",
		"--endpoint", "https://gitlab.internal", "--vendor", "gitlab",
		"--all-projects",
		"--secret-file", filepath.Join(t.TempDir(), "absent"),
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

// TestServeExitsMisconfigured pins the exit-code contract an orchestrator's
// restart policy keys off: 2 means "fix your flags", not "try again".
func TestServeExitsMisconfigured(t *testing.T) {
	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"zenfra-vcs-connector", "--gateway-url", "http://gw"}

	if code := serve(); code != exitMisconfigured {
		t.Fatalf("want exit %d for a misconfiguration, got %d", exitMisconfigured, code)
	}
}

func TestNewLoggerFallsBackOnUnknownLevel(t *testing.T) {
	// An unparseable level must not be fatal — the connector logs at info and
	// keeps serving rather than refusing to start over a typo.
	if !newLogger("nonsense").Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("unknown log level should fall back to info")
	}
	if newLogger("nonsense").Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("fallback should not enable debug")
	}
	if !newLogger("debug").Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("--log-level debug should enable debug")
	}
}

func TestServeMetricsDisabledByDefault(t *testing.T) {
	stop, err := serveMetrics("", metrics.New(time.Unix(0, 0)), newLogger("info"))
	if err != nil {
		t.Fatalf("serveMetrics: %v", err)
	}
	stop()
}

func TestServeMetricsServesTheEndpoint(t *testing.T) {
	collector := metrics.New(time.Unix(0, 0))
	collector.StreamOpened()

	// Port 0: the OS picks a free port, so the test cannot collide with anything.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if closeErr := listener.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	stop, err := serveMetrics(addr, collector, newLogger("info"))
	if err != nil {
		t.Fatalf("serveMetrics: %v", err)
	}
	defer stop()

	var body string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, getErr := http.Get("http://" + addr + "/metrics") //nolint:noctx // test scrape
		if getErr != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		data, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read metrics: %v", readErr)
		}
		body = string(data)
		break
	}
	if !strings.Contains(body, "zenfra_vcs_connector_tunnel_streams 1") {
		t.Fatalf("metrics endpoint did not report the live stream:\n%s", body)
	}
}

func TestServeMetricsUnusableAddressIsTerminal(t *testing.T) {
	// Port 1 is privileged and the host is unroutable for a listener: either way
	// the bind fails, and it must be reported as a configuration problem so the
	// process exits instead of running without the endpoint it was asked for.
	_, err := serveMetrics("203.0.113.1:1", metrics.New(time.Unix(0, 0)), newLogger("info"))
	if !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

// stubRelay stands in for the tunnel in webhook wiring tests.
type stubRelay struct{ calls atomic.Int64 }

func (s *stubRelay) SendEvent(context.Context, *tunnel.Event) (*tunnel.EventAck, error) {
	s.calls.Add(1)
	return &tunnel.EventAck{Accepted: true}, nil
}

func webhookConfig(t *testing.T, addr, secretFile string) *config.Config {
	t.Helper()
	args := []string{
		"--gateway-url", "http://gw",
		"--bootstrap-token", "vcsc_a.b",
		"--endpoint", "http://gitlab.internal",
		"--vendor", "gitlab",
		"--secret-file", "/secrets/vcs-token",
		"--all-projects",
		"--instance-key", "connector-0",
	}
	if addr != "" {
		args = append(args, "--webhook-addr", addr, "--webhook-secret-file", secretFile)
	}
	cfg, err := config.Load(args, noEnv)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	return cfg
}

func TestServeWebhooksDisabledByDefault(t *testing.T) {
	relay := &stubRelay{}
	stop, err := serveWebhooks(webhookConfig(t, "", ""), relay, newLogger("info"))
	if err != nil {
		t.Fatalf("serveWebhooks: %v", err)
	}
	stop()
}

func TestServeWebhooksServesTheEndpoint(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "hook-secret")
	if err := os.WriteFile(secretFile, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if closeErr := listener.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	relay := &stubRelay{}
	stop, err := serveWebhooks(webhookConfig(t, addr, secretFile), relay, newLogger("info"))
	if err != nil {
		t.Fatalf("serveWebhooks: %v", err)
	}
	defer stop()

	deadline := time.Now().Add(5 * time.Second)
	var status int
	for time.Now().Before(deadline) {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"http://"+addr+webhook.Path, strings.NewReader(`{"object_kind":"push"}`))
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		// The trailing newline in the secret file must not be part of the secret.
		req.Header.Set("X-Gitlab-Token", "s3cret")
		req.Header.Set("X-Gitlab-Event", "Push Hook")
		req.Header.Set("X-Gitlab-Event-UUID", "delivery-1")
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		status = resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		break
	}
	if status != http.StatusAccepted {
		t.Fatalf("webhook status = %d, want 202", status)
	}
	if relay.calls.Load() != 1 {
		t.Fatalf("relayed %d events, want 1", relay.calls.Load())
	}
}

func TestServeWebhooksMissingSecretFileIsTerminal(t *testing.T) {
	cfg := webhookConfig(t, "127.0.0.1:0", filepath.Join(t.TempDir(), "absent"))
	if _, err := serveWebhooks(cfg, &stubRelay{}, newLogger("info")); !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestServeWebhooksEmptySecretIsTerminal(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "hook-secret")
	if err := os.WriteFile(secretFile, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := webhookConfig(t, "127.0.0.1:0", secretFile)
	if _, err := serveWebhooks(cfg, &stubRelay{}, newLogger("info")); !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestWarnOptionalModesIsSilentOnTheDefaults(t *testing.T) {
	var buf bytes.Buffer
	warnOptionalModes(&config.Config{
		CredentialMode: config.CredentialModeAgentLocal,
		PolicyMode:     config.PolicyModeAllowlist,
	}, slog.New(slog.NewJSONHandler(&buf, nil)))
	if buf.Len() != 0 {
		t.Fatalf("default configuration warned:\n%s", buf.String())
	}
}

func TestWarnOptionalModesWarnsOnTheOptIns(t *testing.T) {
	var buf bytes.Buffer
	warnOptionalModes(&config.Config{
		CredentialMode: config.CredentialModeControlPlane,
		PolicyMode:     config.PolicyModeBlocklist,
	}, slog.New(slog.NewJSONHandler(&buf, nil)))

	logged := buf.String()
	for _, want := range []string{"WARN", "control_plane", "blocklist"} {
		if !strings.Contains(logged, want) {
			t.Errorf("warning output %q is missing %q", logged, want)
		}
	}
}
