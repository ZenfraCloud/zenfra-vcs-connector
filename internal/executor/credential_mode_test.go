// ABOUTME: Tests for the opt-in control_plane credential mode: the connector forwards a
// ABOUTME: tunneled credential only when configured to, and never learns one otherwise.
package executor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/policy"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// controlPlaneToken is the credential the control plane sends over the tunnel.
const controlPlaneToken = "glpat-FROM-CONTROL-PLANE" //nolint:gosec // fake credential for tests

// newControlPlaneExecutor builds an executor in control_plane credential mode,
// which takes no secret file at all. GitLab is the only vendor the mode allows.
func newControlPlaneExecutor(t *testing.T, endpoint string) (*Executor, *bytes.Buffer) {
	t.Helper()
	cfg, err := config.Load([]string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", "vcsc_abc.def",
		"--endpoint", endpoint,
		"--vendor", "gitlab",
		"--instance-key", "connector-0",
		"--all-projects",
		"--credential-mode", "control_plane",
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	engine, err := policy.NewEngine(cfg)
	if err != nil {
		t.Fatalf("policy.NewEngine() error = %v", err)
	}
	var buf bytes.Buffer
	audit := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	exec, err := New(cfg, engine, audit)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return exec, &buf
}

func TestControlPlaneMode_ForwardsTheTunneledCredential(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":7,"username":"zenfra"}`))
	})
	exec, audit := newControlPlaneExecutor(t, stub.srv.URL)

	w := newFakeResponder()
	exec.Handle(context.Background(), withHeaders(req(http.MethodGet, "/api/v4/user", ""),
		map[string][]string{"PRIVATE-TOKEN": {controlPlaneToken}}), w)

	if got := w.snapshot(); got.failure != nil {
		t.Fatalf("Fail(%q: %q) — want success", got.failure.GetCode(), got.failure.GetMessage())
	}
	upstream, _ := stub.last()
	if token := upstream.Header.Get("PRIVATE-TOKEN"); token != controlPlaneToken {
		t.Errorf("PRIVATE-TOKEN = %q, want the tunneled credential", token)
	}
	if logged := audit.String(); strings.Contains(logged, controlPlaneToken) {
		t.Errorf("audit log contains the credential:\n%s", logged)
	}
}

// control_plane is GitLab-only. For any other vendor the mode would take an
// arbitrary Authorization header off the tunnel and replay it at the customer's
// own server, so the connector refuses to start rather than relying on the
// control plane never to send one.
func TestControlPlaneMode_IsRefusedForNonGitLabVendors(t *testing.T) {
	for _, vendor := range []string{"github", "bitbucket", "azure_devops"} {
		t.Run(vendor, func(t *testing.T) {
			_, err := config.Load([]string{
				"--gateway-url", "https://api.zenfra.cloud",
				"--bootstrap-token", "vcsc_abc.def",
				"--endpoint", "https://vcs.internal",
				"--vendor", vendor,
				"--all-projects",
				"--credential-mode", "control_plane",
			}, func(string) string { return "" })
			if !errors.Is(err, config.ErrInvalidConfig) {
				t.Fatalf("config.Load() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestControlPlaneMode_MissingCredentialIsAnAuthFailure(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	exec, _ := newControlPlaneExecutor(t, stub.srv.URL)

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v4/user", ""), w)

	got := w.snapshot()
	if got.failure == nil || got.failure.GetCode() != tunnel.ErrCodeAuth {
		t.Fatalf("failure = %v, want %s", got.failure, tunnel.ErrCodeAuth)
	}
	if stub.count() != 0 {
		t.Error("a credential-less request reached the upstream")
	}
}

func TestControlPlaneMode_StillRefusesOtherCredentialHeaders(t *testing.T) {
	for _, name := range []string{"Authorization", "Cookie", "X-Api-Key", "Job-Token"} {
		t.Run(name, func(t *testing.T) {
			stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			exec, _ := newControlPlaneExecutor(t, stub.srv.URL)

			w := newFakeResponder()
			exec.Handle(context.Background(), withHeaders(req(http.MethodGet, "/api/v4/user", ""),
				map[string][]string{
					"PRIVATE-TOKEN": {controlPlaneToken},
					name:            {"Bearer stolen"},
				}), w)

			got := w.snapshot()
			if got.failure == nil || got.failure.GetCode() != tunnel.ErrCodeProtocol {
				t.Fatalf("failure = %v, want %s", got.failure, tunnel.ErrCodeProtocol)
			}
			if stub.count() != 0 {
				t.Errorf("request with %s header reached upstream", name)
			}
		})
	}
}

func TestControlPlaneMode_DeniedRequestNeverReachesUpstream(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	exec, _ := newControlPlaneExecutor(t, stub.srv.URL)

	w := newFakeResponder()
	exec.Handle(context.Background(), withHeaders(req(http.MethodDelete, "/api/v4/projects/42", ""),
		map[string][]string{"PRIVATE-TOKEN": {controlPlaneToken}}), w)

	got := w.snapshot()
	if got.failure == nil || got.failure.GetCode() != tunnel.ErrCodePolicyDenied {
		t.Fatalf("failure = %v, want %s", got.failure, tunnel.ErrCodePolicyDenied)
	}
	if stub.count() != 0 {
		t.Error("a policy-denied request reached the upstream")
	}
}

func TestAgentLocalMode_RefusesATunneledCredential(t *testing.T) {
	// The default mode is the guarantee this whole feature is opt-in from: a
	// connector that was not configured for it refuses the injected credential.
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	exec, _ := newExecutor(t, stub.srv.URL, newSecretFile(t, testSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(), withHeaders(req(http.MethodGet, "/api/v4/user", ""),
		map[string][]string{"PRIVATE-TOKEN": {controlPlaneToken}}), w)

	got := w.snapshot()
	if got.failure == nil || got.failure.GetCode() != tunnel.ErrCodeProtocol {
		t.Fatalf("failure = %v, want %s", got.failure, tunnel.ErrCodeProtocol)
	}
	if stub.count() != 0 {
		t.Error("an injected credential reached the upstream in agent_local mode")
	}
}
