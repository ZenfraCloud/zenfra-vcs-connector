// ABOUTME: Tests for the Bitbucket Data Center upstream: bearer credential and the identity header.
// ABOUTME: Bitbucket serves archives itself, so no rule here may follow a redirect anywhere.
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

// bitbucketSecret is the Bitbucket HTTP access token; no test output may contain it.
const bitbucketSecret = "BBDC-SUPERSECRET-do-not-log" //nolint:gosec // fake credential for tests

func newBitbucketExecutor(
	t *testing.T, endpoint, secretPath string, projects ...string,
) (*Executor, *bytes.Buffer) {
	t.Helper()
	args := []string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", "vcsc_abc.def",
		"--endpoint", endpoint,
		"--vendor", "bitbucket",
		"--secret-file", secretPath,
		"--instance-key", "connector-0",
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

// Bitbucket Data Center authenticates HTTP access tokens as bearer credentials
// and names the authenticated user in X-AUSERNAME, which is how verify observes
// an identity without a "current user" endpoint.
func TestHandle_BitbucketInjectsBearerCredentialAndReturnsIdentity(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-AUSERNAME", "zenfra-bot")
		// A session cookie must never cross back into the control plane.
		w.Header().Set("Set-Cookie", "BITBUCKETSESSIONID=abc; Path=/")
		_, _ = w.Write([]byte(`{"size":1,"values":[{"slug":"zenfra-bot"}]}`))
	})
	exec, audit := newBitbucketExecutor(t, stub.srv.URL, newSecretFile(t, bitbucketSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/rest/api/1.0/users", "limit=1"), w)

	got := w.snapshot()
	if got.failure != nil {
		t.Fatalf("Fail(%q: %s) — want success", got.failure.GetCode(), got.failure.GetMessage())
	}
	if got.status != http.StatusOK {
		t.Errorf("status = %d, want 200", got.status)
	}
	upstream, _ := stub.last()
	if auth := upstream.Header.Get("Authorization"); auth != "Bearer "+bitbucketSecret {
		t.Errorf("Authorization = %q, want a bearer credential", auth)
	}
	if token := upstream.Header.Get("PRIVATE-TOKEN"); token != "" {
		t.Errorf("PRIVATE-TOKEN = %q, want the GitLab header absent", token)
	}
	if user := got.header.Get("X-Ausername"); user != "zenfra-bot" {
		t.Errorf("X-AUSERNAME = %q, want the identity header to cross back", user)
	}
	if cookie := got.header.Get("Set-Cookie"); cookie != "" {
		t.Errorf("Set-Cookie = %q, want the upstream session dropped", cookie)
	}
	if rule := got.header.Get(tunnel.HeaderPolicyRule); rule != "bitbucket.user.current" {
		t.Errorf("%s = %q, want bitbucket.user.current", tunnel.HeaderPolicyRule, rule)
	}
	if strings.Contains(audit.String(), bitbucketSecret) {
		t.Error("audit log contains the credential")
	}
}

// The archive comes from the API host itself. A redirect is not followed, so a
// hostile Location cannot move the download — or the credential — anywhere.
func TestHandle_BitbucketArchiveNeverFollowsARedirect(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://attacker.invalid/archive.tar.gz")
		w.WriteHeader(http.StatusFound)
	})
	exec, _ := newBitbucketExecutor(t, stub.srv.URL, newSecretFile(t, bitbucketSecret))

	r := req(http.MethodGet,
		"/rest/api/1.0/projects/ENG/repos/platform/archive", "format=tar.gz&at=main")
	r.Head.DeadlineClass = tunnel.DeadlineClass_DEADLINE_CLASS_BULK
	w := newFakeResponder()
	exec.Handle(context.Background(), r, w)

	got := w.snapshot()
	if got.failure != nil {
		t.Fatalf("Fail(%q: %s) — want the redirect reported verbatim", got.failure.GetCode(), got.failure.GetMessage())
	}
	// The 302 is handed back as-is: only a rule that names a pinned origin may
	// follow one, and Bitbucket has no second origin.
	if got.status != http.StatusFound {
		t.Errorf("status = %d, want the 302 passed through unfollowed", got.status)
	}
	if got.header.Get("Location") != "" {
		t.Error("Location crossed back to the control plane, want it dropped")
	}
	if stub.count() != 1 {
		t.Errorf("upstream received %d requests, want 1 (no redirect followed)", stub.count())
	}
}

// Project scoping spans two path segments on Bitbucket; a repository outside
// --allowed-projects is denied before the credential is ever read.
func TestHandle_BitbucketDeniesOutOfScopeRepository(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	exec, _ := newBitbucketExecutor(t, stub.srv.URL, newSecretFile(t, bitbucketSecret), "ENG/platform")

	w := newFakeResponder()
	exec.Handle(context.Background(),
		req(http.MethodGet, "/rest/api/1.0/projects/ENG/repos/secrets/branches", ""), w)

	got := w.snapshot()
	if got.failure == nil {
		t.Fatal("Fail() not called, want a policy denial")
	}
	if got.failure.GetCode() != tunnel.ErrCodePolicyDenied {
		t.Errorf("code = %q, want %q", got.failure.GetCode(), tunnel.ErrCodePolicyDenied)
	}
	if stub.count() != 0 {
		t.Errorf("upstream received %d requests, want 0", stub.count())
	}
}
