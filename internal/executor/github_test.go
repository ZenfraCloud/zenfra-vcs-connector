// ABOUTME: Tests for the GitHub Enterprise upstream: bearer credential and the pinned codeload origin.
// ABOUTME: A hostile Location header must never move a download off the operator's configured origin.
package executor

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/policy"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// gheSecret is the GitHub Enterprise credential; no test output may contain it.
const gheSecret = "ghp_SUPERSECRET-do-not-log" //nolint:gosec // fake credential for tests

// newGitHubExecutor builds a GitHub Enterprise executor with a pinned codeload
// origin. Empty codeload means the flag is unset, which pins it to the endpoint.
func newGitHubExecutor(
	t *testing.T, endpoint, codeload, secretPath string, projects ...string,
) (*Executor, *bytes.Buffer) {
	t.Helper()
	args := []string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", "vcsc_abc.def",
		"--endpoint", endpoint,
		"--vendor", "github",
		"--secret-file", secretPath,
		"--instance-key", "connector-0",
	}
	if codeload != "" {
		args = append(args, "--codeload-endpoint", codeload)
	}
	if len(projects) == 0 {
		args = append(args, "--all-projects")
	} else {
		args = append(args, "--allowed-projects", strings.Join(projects, ","))
	}
	cfg, err := config.Load(args, func(string) string { return "" })
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

func TestHandle_GitHubInjectsBearerCredential(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":7,"login":"zenfra"}`))
	})
	exec, _ := newGitHubExecutor(t, stub.srv.URL, "", newSecretFile(t, gheSecret))

	w := newFakeResponder()
	r := withHeaders(req(http.MethodGet, "/api/v3/user", ""), map[string][]string{
		"X-GitHub-Api-Version": {"2022-11-28"},
	})
	exec.Handle(context.Background(), r, w)

	got := w.snapshot()
	if got.failure != nil {
		t.Fatalf("Fail(%q: %s) — want success", got.failure.GetCode(), got.failure.GetMessage())
	}
	if got.status != http.StatusOK {
		t.Errorf("status = %d, want 200", got.status)
	}
	upstream, _ := stub.last()
	if auth := upstream.Header.Get("Authorization"); auth != "Bearer "+gheSecret {
		t.Errorf("Authorization = %q, want a bearer credential", auth)
	}
	if token := upstream.Header.Get("PRIVATE-TOKEN"); token != "" {
		t.Errorf("PRIVATE-TOKEN = %q, want the GitLab header absent", token)
	}
	if version := upstream.Header.Get("X-GitHub-Api-Version"); version != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version = %q, want the caller's pin to cross", version)
	}
	if rule := got.header.Get(tunnel.HeaderPolicyRule); rule != "github.user.current" {
		t.Errorf("%s = %q, want github.user.current", tunnel.HeaderPolicyRule, rule)
	}
}

// The archive redirect is followed onto the operator's pinned codeload origin.
// The Location header names a host the connector has never heard of; only its
// path is used, and the credential does not travel to the second origin.
func TestHandle_ArchiveRedirectGoesToThePinnedCodeloadOrigin(t *testing.T) {
	codeload := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write([]byte("archive-bytes"))
	})
	api := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://attacker.invalid/_codeload/eng/platform/legacy.tar.gz/abc123")
		w.WriteHeader(http.StatusFound)
	})
	exec, audit := newGitHubExecutor(t, api.srv.URL, codeload.srv.URL, newSecretFile(t, gheSecret))

	r := req(http.MethodGet, "/api/v3/repos/eng/platform/tarball/abc123", "")
	r.Head.DeadlineClass = tunnel.DeadlineClass_DEADLINE_CLASS_BULK
	w := newFakeResponder()
	exec.Handle(context.Background(), r, w)

	got := w.snapshot()
	if got.failure != nil {
		t.Fatalf("Fail(%q: %s) — want the archive", got.failure.GetCode(), got.failure.GetMessage())
	}
	if got.status != http.StatusOK {
		t.Errorf("status = %d, want 200 from the codeload origin", got.status)
	}
	if body := w.bodyString(); body != "archive-bytes" {
		t.Errorf("body = %q, want the archive bytes", body)
	}
	if codeload.count() != 1 {
		t.Fatalf("codeload origin received %d requests, want 1", codeload.count())
	}
	followed, _ := codeload.last()
	if want := "/_codeload/eng/platform/legacy.tar.gz/abc123"; followed.URL.Path != want {
		t.Errorf("codeload path = %q, want %q", followed.URL.Path, want)
	}
	// SECURITY: the second origin is a different host in general, so the upstream
	// credential must not follow the redirect onto it.
	if auth := followed.Header.Get("Authorization"); auth != "" {
		t.Errorf("Authorization = %q on the codeload leg, want none", auth)
	}
	if log := audit.String(); !strings.Contains(log, "codeload") {
		t.Errorf("audit log = %s, want it to record the followed origin", log)
	}
	if strings.Contains(audit.String(), gheSecret) {
		t.Error("audit log contains the credential")
	}
}

// With no --codeload-endpoint the pinned origin is the endpoint itself, which is
// how GitHub Enterprise serves /_codeload by default.
func TestHandle_ArchiveRedirectDefaultsToTheEndpoint(t *testing.T) {
	api := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/_codeload/") {
			_, _ = w.Write([]byte("archive-bytes"))
			return
		}
		w.Header().Set("Location", "/_codeload/eng/platform/legacy.tar.gz/abc123")
		w.WriteHeader(http.StatusFound)
	})
	exec, _ := newGitHubExecutor(t, api.srv.URL, "", newSecretFile(t, gheSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v3/repos/eng/platform/tarball/abc123", ""), w)

	if got := w.snapshot(); got.failure != nil {
		t.Fatalf("Fail(%q: %s) — want the archive", got.failure.GetCode(), got.failure.GetMessage())
	}
	if api.count() != 2 {
		t.Fatalf("endpoint received %d requests, want 2 (tarball then codeload)", api.count())
	}
	followed, _ := api.last()
	if want := "/_codeload/eng/platform/legacy.tar.gz/abc123"; followed.URL.Path != want {
		t.Errorf("followed path = %q, want %q", followed.URL.Path, want)
	}
	if body := w.bodyString(); body != "archive-bytes" {
		t.Errorf("body = %q, want the archive bytes", body)
	}
}

func TestHandle_RedirectToAnUnallowedPathIsDenied(t *testing.T) {
	codeload := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should never be reached"))
	})
	api := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		// A path on the pinned origin that no codeload rule allows.
		w.Header().Set("Location", "/_codeload/eng/platform/../../etc/passwd")
		w.WriteHeader(http.StatusFound)
	})
	exec, _ := newGitHubExecutor(t, api.srv.URL, codeload.srv.URL, newSecretFile(t, gheSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v3/repos/eng/platform/tarball/abc123", ""), w)

	got := w.snapshot()
	if got.failure == nil {
		t.Fatal("Fail() was never called, want policy_denied")
	}
	if code := got.failure.GetCode(); code != tunnel.ErrCodePolicyDenied {
		t.Errorf("code = %q, want %q", code, tunnel.ErrCodePolicyDenied)
	}
	if codeload.count() != 0 {
		t.Errorf("codeload origin received %d requests, want 0", codeload.count())
	}
}

// A redirect to a repository outside --allowed-projects is refused even though
// its shape is a legitimate archive path.
func TestHandle_RedirectOutsideProjectScopeIsDenied(t *testing.T) {
	api := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/_codeload/other/secret/legacy.tar.gz/abc123")
		w.WriteHeader(http.StatusFound)
	})
	exec, _ := newGitHubExecutor(t, api.srv.URL, "", newSecretFile(t, gheSecret), "eng/platform")

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v3/repos/eng/platform/tarball/abc123", ""), w)

	got := w.snapshot()
	if got.failure == nil {
		t.Fatal("Fail() was never called, want policy_denied")
	}
	if code := got.failure.GetCode(); code != tunnel.ErrCodePolicyDenied {
		t.Errorf("code = %q, want %q", code, tunnel.ErrCodePolicyDenied)
	}
}

// Only rules that declare a redirect target follow one. Everything else reports
// the redirect as the upstream's own answer.
func TestHandle_RedirectOnANonArchiveRuleIsNotFollowed(t *testing.T) {
	api := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://attacker.invalid/api/v3/user")
		w.WriteHeader(http.StatusFound)
	})
	exec, _ := newGitHubExecutor(t, api.srv.URL, "", newSecretFile(t, gheSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v3/user", ""), w)

	got := w.snapshot()
	if got.status != http.StatusFound {
		t.Errorf("status = %d, want the 302 reported as-is", got.status)
	}
	if api.count() != 1 {
		t.Errorf("upstream received %d requests, want 1", api.count())
	}
	if location := got.header.Get("Location"); location != "" {
		t.Errorf("Location = %q, want it withheld from the control plane", location)
	}
}

func TestHandle_RedirectWithoutALocationFails(t *testing.T) {
	api := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusFound)
	})
	exec, _ := newGitHubExecutor(t, api.srv.URL, "", newSecretFile(t, gheSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v3/repos/eng/platform/tarball/abc123", ""), w)

	got := w.snapshot()
	if got.failure == nil {
		t.Fatal("Fail() was never called, want an upstream error")
	}
	if code := got.failure.GetCode(); code != tunnel.ErrCodeUpstreamHTTP {
		t.Errorf("code = %q, want %q", code, tunnel.ErrCodeUpstreamHTTP)
	}
}

func TestHandle_CodeloadOriginUnreachableReportsUpstream(t *testing.T) {
	api := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/_codeload/eng/platform/legacy.tar.gz/abc123")
		w.WriteHeader(http.StatusFound)
	})
	// Port 1 is closed: the pinned origin exists in config but not on the network.
	exec, _ := newGitHubExecutor(t, api.srv.URL, "https://127.0.0.1:1", newSecretFile(t, gheSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/api/v3/repos/eng/platform/tarball/abc123", ""), w)

	got := w.snapshot()
	if got.failure == nil {
		t.Fatal("Fail() was never called, want an upstream error")
	}
	if code := got.failure.GetCode(); code != tunnel.ErrCodeUpstreamConn && code != tunnel.ErrCodeUpstreamTLS {
		t.Errorf("code = %q, want an upstream connection failure", code)
	}
	if got.headSent {
		t.Error("a response head was sent for a failed follow")
	}
}
