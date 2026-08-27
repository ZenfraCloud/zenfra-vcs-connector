// ABOUTME: Tests for the Azure DevOps Server upstream: HTTP Basic PAT injection and scoping.
// ABOUTME: The collection lives in --endpoint, so a tunneled path lands under it, never beside it.
package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/policy"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// azureDevOpsSecret is the Azure DevOps PAT; no test output may contain it.
const azureDevOpsSecret = "ADO-SUPERSECRET-do-not-log" //nolint:gosec // fake credential for tests

func newAzureDevOpsExecutor(
	t *testing.T, endpoint, secretPath string, projects ...string,
) (*Executor, *bytes.Buffer) {
	t.Helper()
	args := []string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", "vcsc_abc.def",
		"--endpoint", endpoint,
		"--vendor", "azure_devops",
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

// Azure DevOps takes a PAT as HTTP Basic with an empty username — a bearer
// header authenticates nothing there.
func TestHandle_AzureDevOpsInjectsBasicCredential(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-MS-ContinuationToken", "next-page")
		_, _ = w.Write([]byte(`{"authenticatedUser":{"providerDisplayName":"zenfra-bot"}}`))
	})
	exec, audit := newAzureDevOpsExecutor(t, stub.srv.URL, newSecretFile(t, azureDevOpsSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(), req(http.MethodGet, "/_apis/connectionData", "api-version=6.0"), w)

	got := w.snapshot()
	if got.failure != nil {
		t.Fatalf("Fail(%q: %s) — want success", got.failure.GetCode(), got.failure.GetMessage())
	}
	upstream, _ := stub.last()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+azureDevOpsSecret))
	if auth := upstream.Header.Get("Authorization"); auth != want {
		t.Errorf("Authorization = %q, want an HTTP Basic credential", auth)
	}
	if token := upstream.Header.Get("PRIVATE-TOKEN"); token != "" {
		t.Errorf("PRIVATE-TOKEN = %q, want the GitLab header absent", token)
	}
	// Paging state lives in a response header on Azure DevOps, so it has to cross back.
	if next := got.header.Get("X-Ms-Continuationtoken"); next != "next-page" {
		t.Errorf("X-MS-ContinuationToken = %q, want the paging token forwarded", next)
	}
	if rule := got.header.Get(tunnel.HeaderPolicyRule); rule != "azure_devops.connection_data" {
		t.Errorf("%s = %q, want azure_devops.connection_data", tunnel.HeaderPolicyRule, rule)
	}
	if strings.Contains(audit.String(), azureDevOpsSecret) {
		t.Error("audit log contains the credential")
	}
}

// The collection is part of the operator's --endpoint, so an approved path is
// appended to it: nothing on the wire can move a request out of the collection.
func TestHandle_AzureDevOpsRequestLandsUnderTheConfiguredCollection(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"count":0,"value":[]}`))
	})
	exec, _ := newAzureDevOpsExecutor(t,
		stub.srv.URL+"/DefaultCollection", newSecretFile(t, azureDevOpsSecret))

	w := newFakeResponder()
	exec.Handle(context.Background(),
		req(http.MethodGet, "/Platform/_apis/git/repositories/infra/refs", "api-version=6.0"), w)

	if got := w.snapshot(); got.failure != nil {
		t.Fatalf("Fail(%q: %s) — want success", got.failure.GetCode(), got.failure.GetMessage())
	}
	upstream, _ := stub.last()
	if want := "/DefaultCollection/Platform/_apis/git/repositories/infra/refs"; upstream.URL.Path != want {
		t.Errorf("upstream path = %q, want %q", upstream.URL.Path, want)
	}
}

// The archive is the items resource with $format=zip and comes from the
// collection host itself; a redirect is never followed.
func TestHandle_AzureDevOpsArchiveNeverFollowsARedirect(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://attacker.invalid/archive.zip")
		w.WriteHeader(http.StatusFound)
	})
	exec, _ := newAzureDevOpsExecutor(t, stub.srv.URL, newSecretFile(t, azureDevOpsSecret))

	r := req(http.MethodGet, "/Platform/_apis/git/repositories/infra/items",
		"path=%2F&%24format=zip&api-version=6.0")
	r.Head.DeadlineClass = tunnel.DeadlineClass_DEADLINE_CLASS_BULK
	w := newFakeResponder()
	exec.Handle(context.Background(), r, w)

	got := w.snapshot()
	if got.failure != nil {
		t.Fatalf("Fail(%q: %s) — want the redirect reported verbatim", got.failure.GetCode(), got.failure.GetMessage())
	}
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

// Project scoping spans the project and repository segments; a repository
// outside --allowed-projects is denied before the credential is ever read.
func TestHandle_AzureDevOpsDeniesOutOfScopeRepository(t *testing.T) {
	stub := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	exec, _ := newAzureDevOpsExecutor(t, stub.srv.URL,
		newSecretFile(t, azureDevOpsSecret), "Platform/infra")

	w := newFakeResponder()
	exec.Handle(context.Background(),
		req(http.MethodGet, "/Platform/_apis/git/repositories/secrets/refs", "api-version=6.0"), w)

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
