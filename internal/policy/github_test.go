// ABOUTME: Tests for the compiled GitHub Enterprise allowlist and its pinned codeload origin.
// ABOUTME: Proves archive downloads reach a second endpoint by rule, never by rewriting a redirect.
package policy

import (
	"strings"
	"testing"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
)

// gheEngine builds a GitHub Enterprise engine scoped to the given repositories;
// empty means all-projects.
func gheEngine(t *testing.T, repos ...string) *Engine {
	t.Helper()
	cfg := &config.Config{
		Vendor:          config.VendorGitHub,
		AllowedProjects: repos,
		AllProjects:     len(repos) == 0,
	}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v, want nil", err)
	}
	return e
}

func TestAllowlistCoversTheGitHubEnterpriseSurface(t *testing.T) {
	tests := []struct {
		method      string
		path        string
		wantRule    string
		wantProject string
	}{
		{"GET", "/api/v3/user", "github.user.current", ""},
		{"GET", "/api/v3/user/repos", "github.repos.list", ""},
		{"GET", "/api/v3/repos/eng/platform", "github.repo.get", "eng/platform"},
		{"GET", "/api/v3/repos/eng/platform/contents", "github.repo.contents", "eng/platform"},
		{"GET", "/api/v3/repos/eng/platform/contents/infra/main.tf", "github.repo.contents", "eng/platform"},
		{"GET", "/api/v3/repos/eng/platform/branches", "github.branches.list", "eng/platform"},
		{"GET", "/api/v3/repos/eng/platform/branches/main", "github.branch.get", "eng/platform"},
		{"GET", "/api/v3/repos/eng/platform/commits", "github.commits.list", "eng/platform"},
		{"GET", "/api/v3/repos/eng/platform/commits/abc123", "github.commit.get", "eng/platform"},
		{"GET", "/api/v3/repos/eng/platform/compare/main...topic", "github.compare", "eng/platform"},
		{"GET", "/api/v3/repos/eng/platform/tarball/abc123", "github.repository.tarball", "eng/platform"},
		{"GET", "/api/v3/repos/eng/platform/pulls", "github.pull_requests.list", "eng/platform"},
		{"GET", "/api/v3/repos/eng/platform/pulls/7", "github.pull_request.get", "eng/platform"},
		{"GET", "/api/v3/repos/eng/platform/pulls/7/files", "github.pull_request.files", "eng/platform"},
		{
			"GET", "/api/v3/repos/eng/platform/issues/7/comments",
			"github.pull_request.comments.list", "eng/platform",
		},
		{
			"POST", "/api/v3/repos/eng/platform/issues/7/comments",
			"github.pull_request.comment.create", "eng/platform",
		},
		{
			"PATCH", "/api/v3/repos/eng/platform/issues/comments/9",
			"github.pull_request.comment.update", "eng/platform",
		},
		{"POST", "/api/v3/repos/eng/platform/check-runs", "github.check_run.create", "eng/platform"},
		{"PATCH", "/api/v3/repos/eng/platform/check-runs/11", "github.check_run.update", "eng/platform"},
		{"POST", "/api/v3/repos/eng/platform/statuses/abc123", "github.commit.status.create", "eng/platform"},
	}
	e := gheEngine(t)
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			dec := e.Evaluate(tt.method, tt.path, "")
			if !dec.Allowed {
				t.Fatalf("Evaluate(%s %s) denied: %s", tt.method, tt.path, dec.Reason)
			}
			if dec.RuleID != tt.wantRule {
				t.Errorf("RuleID = %q, want %q", dec.RuleID, tt.wantRule)
			}
			if dec.Purpose == "" {
				t.Error("Purpose is empty, want a human-readable operation name")
			}
			if dec.Project != tt.wantProject {
				t.Errorf("Project = %q, want %q", dec.Project, tt.wantProject)
			}
			if dec.Origin != OriginPrimary {
				t.Errorf("Origin = %q, want %q", dec.Origin, OriginPrimary)
			}
		})
	}
}

func TestGitHubAllowlistDeniesEverythingElse(t *testing.T) {
	denied := []struct{ method, path string }{
		{"DELETE", "/api/v3/repos/eng/platform"},
		{"PUT", "/api/v3/repos/eng/platform/contents/main.tf"},
		{"POST", "/api/v3/repos/eng/platform/pulls"},
		{"POST", "/api/v3/repos/eng/platform/merges"},
		{"GET", "/api/v3/admin/users"},
		{"GET", "/api/v3/repos/eng/platform/keys"},
		{"GET", "/api/v3/repos/eng/platform/actions/secrets"},
		// Smart-HTTP git: archives travel the bulk lane, not git protocol.
		{"GET", "/eng/platform.git/info/refs"},
	}
	e := gheEngine(t)
	for _, tt := range denied {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			dec := e.Evaluate(tt.method, tt.path, "")
			if dec.Allowed {
				t.Fatalf("Evaluate(%s %s) allowed by rule %s, want denied", tt.method, tt.path, dec.RuleID)
			}
			if dec.Reason == "" {
				t.Error("Reason is empty, want it to say why")
			}
		})
	}
}

func TestGitHubProjectScopingUsesOwnerRepo(t *testing.T) {
	e := gheEngine(t, "eng/platform")

	if dec := e.Evaluate("GET", "/api/v3/repos/eng/platform/branches", ""); !dec.Allowed {
		t.Fatalf("in-scope repository denied: %s", dec.Reason)
	}
	// Case folding: operators type the repository either way.
	if dec := e.Evaluate("GET", "/api/v3/repos/Eng/Platform/branches", ""); !dec.Allowed {
		t.Fatalf("in-scope repository denied on case: %s", dec.Reason)
	}
	dec := e.Evaluate("GET", "/api/v3/repos/other/secret/branches", "")
	if dec.Allowed {
		t.Fatal("out-of-scope repository allowed, want denied")
	}
	if !strings.Contains(dec.Reason, "other/secret") {
		t.Errorf("Reason = %q, want it to name the out-of-scope repository", dec.Reason)
	}
	// The identity call is repository-independent and must stay reachable.
	if dec := e.Evaluate("GET", "/api/v3/user", ""); !dec.Allowed {
		t.Fatalf("repository-independent rule denied: %s", dec.Reason)
	}
}

// The tarball endpoint answers with a redirect. The rule — not the redirect —
// declares which pinned origin may serve the follow-up.
func TestTarballRuleRedirectsToTheCodeloadOrigin(t *testing.T) {
	e := gheEngine(t)

	dec := e.Evaluate("GET", "/api/v3/repos/eng/platform/tarball/abc123", "")
	if !dec.Allowed {
		t.Fatalf("tarball denied: %s", dec.Reason)
	}
	if dec.Origin != OriginPrimary {
		t.Errorf("Origin = %q, want %q", dec.Origin, OriginPrimary)
	}
	if dec.RedirectsTo != OriginCodeload {
		t.Errorf("RedirectsTo = %q, want %q", dec.RedirectsTo, OriginCodeload)
	}

	// Every other rule refuses to follow anything at all.
	other := e.Evaluate("GET", "/api/v3/user", "")
	if other.RedirectsTo != "" {
		t.Errorf("RedirectsTo = %q for %s, want empty", other.RedirectsTo, other.RuleID)
	}
}

func TestCodeloadRulesAreScopedAndPinnedToTheirOrigin(t *testing.T) {
	tests := []struct {
		name, path, wantRule string
	}{
		{
			name:     "enterprise codeload path",
			path:     "/_codeload/eng/platform/legacy.tar.gz/abc123",
			wantRule: "github.codeload.archive",
		},
		{
			name:     "dedicated codeload host path",
			path:     "/eng/platform/legacy.tar.gz/abc123",
			wantRule: "github.codeload.archive.host",
		},
	}
	e := gheEngine(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.Evaluate("GET", tt.path, "")
			if !dec.Allowed {
				t.Fatalf("Evaluate(GET %s) denied: %s", tt.path, dec.Reason)
			}
			if dec.RuleID != tt.wantRule {
				t.Errorf("RuleID = %q, want %q", dec.RuleID, tt.wantRule)
			}
			if dec.Origin != OriginCodeload {
				t.Errorf("Origin = %q, want %q", dec.Origin, OriginCodeload)
			}
			if dec.Project != "eng/platform" {
				t.Errorf("Project = %q, want eng/platform", dec.Project)
			}
		})
	}

	// Scoping applies on the codeload lane too: it is a repository download.
	scoped := gheEngine(t, "eng/platform")
	if dec := scoped.Evaluate("GET", "/_codeload/other/secret/legacy.tar.gz/abc123", ""); dec.Allowed {
		t.Fatal("out-of-scope codeload download allowed, want denied")
	}
	// A codeload origin is not a general proxy: only archive paths match.
	if dec := scoped.Evaluate("GET", "/_codeload/eng/platform/config/secrets", ""); dec.Allowed {
		t.Fatalf("non-archive codeload path allowed by rule %s, want denied", dec.RuleID)
	}
}

func TestPolicyHashDiffersPerVendor(t *testing.T) {
	if gitLab, gitHub := engine(t).PolicyHash(), gheEngine(t).PolicyHash(); gitLab == gitHub {
		t.Errorf("PolicyHash() = %q for both vendors, want distinct fingerprints", gitLab)
	}
}
