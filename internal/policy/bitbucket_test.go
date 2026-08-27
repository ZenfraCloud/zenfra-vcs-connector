// ABOUTME: Tests for the compiled Bitbucket Data Center allowlist (/rest/api/1.0).
// ABOUTME: Covers the endpoint surface, project/repo scoping and canonicalization of encoded paths.
package policy

import (
	"strings"
	"testing"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
)

// bitbucketEngine builds a Bitbucket Data Center engine scoped to the given
// PROJECT/repo pairs; empty means all-projects.
func bitbucketEngine(t *testing.T, repos ...string) *Engine {
	t.Helper()
	cfg := &config.Config{
		Vendor:          config.VendorBitbucket,
		AllowedProjects: repos,
		AllProjects:     len(repos) == 0,
	}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v, want nil", err)
	}
	return e
}

func TestAllowlistCoversTheBitbucketDataCenterSurface(t *testing.T) {
	const repo = "/rest/api/1.0/projects/ENG/repos/platform"
	tests := []struct {
		method      string
		path        string
		wantRule    string
		wantProject string
	}{
		{"GET", "/rest/api/1.0/users", "bitbucket.user.current", ""},
		{"GET", "/rest/api/1.0/repos", "bitbucket.repos.list", ""},
		{"GET", repo, "bitbucket.repo.get", "ENG/platform"},
		{"GET", repo + "/browse", "bitbucket.repo.browse", "ENG/platform"},
		{"GET", repo + "/browse/infra/main.tf", "bitbucket.repo.browse", "ENG/platform"},
		{"GET", repo + "/raw/infra/main.tf", "bitbucket.repo.raw", "ENG/platform"},
		{"GET", repo + "/branches", "bitbucket.branches.list", "ENG/platform"},
		{"GET", repo + "/branches/default", "bitbucket.branches.default", "ENG/platform"},
		{"GET", repo + "/commits", "bitbucket.commits.list", "ENG/platform"},
		{"GET", repo + "/commits/abc123", "bitbucket.commit.get", "ENG/platform"},
		{"GET", repo + "/commits/abc123/diff", "bitbucket.commit.diff", "ENG/platform"},
		{"GET", repo + "/commits/abc123/changes", "bitbucket.commit.changes", "ENG/platform"},
		{"GET", repo + "/archive", "bitbucket.repository.archive", "ENG/platform"},
		{"GET", repo + "/pull-requests", "bitbucket.pull_requests.list", "ENG/platform"},
		{"GET", repo + "/pull-requests/7", "bitbucket.pull_request.get", "ENG/platform"},
		{"GET", repo + "/pull-requests/7/changes", "bitbucket.pull_request.changes", "ENG/platform"},
		{"GET", repo + "/pull-requests/7/diff", "bitbucket.pull_request.diff", "ENG/platform"},
		{
			"GET", repo + "/pull-requests/7/comments",
			"bitbucket.pull_request.comments.list", "ENG/platform",
		},
		{
			"POST", repo + "/pull-requests/7/comments",
			"bitbucket.pull_request.comment.create", "ENG/platform",
		},
		{
			"PUT", repo + "/pull-requests/7/comments/9",
			"bitbucket.pull_request.comment.update", "ENG/platform",
		},
		{"GET", repo + "/commits/abc123/builds", "bitbucket.build_statuses.list", "ENG/platform"},
		{"POST", repo + "/commits/abc123/builds", "bitbucket.build_status.set", "ENG/platform"},
	}
	e := bitbucketEngine(t)
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
			// Bitbucket serves archives from the API host itself, so there is no
			// second origin and nothing may follow a redirect.
			if dec.Origin != OriginPrimary {
				t.Errorf("Origin = %q, want %q", dec.Origin, OriginPrimary)
			}
			if dec.RedirectsTo != "" {
				t.Errorf("RedirectsTo = %q, want empty", dec.RedirectsTo)
			}
		})
	}
}

func TestBitbucketAllowlistDeniesEverythingElse(t *testing.T) {
	const repo = "/rest/api/1.0/projects/ENG/repos/platform"
	denied := []struct{ method, path string }{
		{"DELETE", repo},
		{"PUT", repo + "/browse/main.tf"},
		{"POST", repo + "/pull-requests"},
		{"POST", repo + "/pull-requests/7/merge"},
		{"GET", repo + "/permissions/users"},
		{"GET", repo + "/settings/hooks"},
		{"GET", "/rest/api/1.0/admin/users"},
		{"GET", "/rest/api/1.0/admin/license"},
		{"POST", "/rest/api/1.0/users/credentials"},
		// The legacy unscoped build-status API bypasses --allowed-projects.
		{"POST", "/rest/build-status/1.0/commits/abc123"},
		// Smart-HTTP git: archives travel the bulk lane, not git protocol.
		{"GET", "/scm/ENG/platform.git/info/refs"},
	}
	e := bitbucketEngine(t)
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

// Bitbucket splits the repository identity across two path segments; scoping
// still compares the "PROJECT/repo" string an operator configures.
func TestBitbucketProjectScopingJoinsProjectAndRepo(t *testing.T) {
	e := bitbucketEngine(t, "ENG/platform")

	if dec := e.Evaluate("GET", "/rest/api/1.0/projects/ENG/repos/platform/branches", ""); !dec.Allowed {
		t.Fatalf("in-scope repository denied: %s", dec.Reason)
	}
	// Case folding: project keys are upper-case but operators type either way.
	if dec := e.Evaluate("GET", "/rest/api/1.0/projects/eng/repos/Platform/branches", ""); !dec.Allowed {
		t.Fatalf("in-scope repository denied on case: %s", dec.Reason)
	}
	// A different repo in the same project is a different scope.
	dec := e.Evaluate("GET", "/rest/api/1.0/projects/ENG/repos/secrets/branches", "")
	if dec.Allowed {
		t.Fatal("out-of-scope repository allowed, want denied")
	}
	if !strings.Contains(dec.Reason, "ENG/secrets") {
		t.Errorf("Reason = %q, want it to name the out-of-scope repository", dec.Reason)
	}
	// Same repo name under another project is also out of scope.
	if dec := e.Evaluate("GET", "/rest/api/1.0/projects/OTHER/repos/platform/branches", ""); dec.Allowed {
		t.Fatal("out-of-scope project allowed, want denied")
	}
	// The identity call is repository-independent and must stay reachable.
	if dec := e.Evaluate("GET", "/rest/api/1.0/users", ""); !dec.Allowed {
		t.Fatalf("repository-independent rule denied: %s", dec.Reason)
	}
}

// Canonicalization runs before matching, so what the allowlist approved is
// exactly the bytes the executor sends.
func TestBitbucketCanonicalizationBeforeMatch(t *testing.T) {
	e := bitbucketEngine(t, "ENG/platform")

	// Percent-escape hex is uppercased; structure is never rewritten.
	dec := e.Evaluate("GET", "/rest/api/1.0/projects/ENG/repos/platform/raw/infra%2fmain.tf", "at=main")
	if !dec.Allowed {
		t.Fatalf("encoded path denied: %s", dec.Reason)
	}
	if want := "/rest/api/1.0/projects/ENG/repos/platform/raw/infra%2Fmain.tf"; dec.Path != want {
		t.Errorf("Path = %q, want %q", dec.Path, want)
	}
	if dec.Query != "at=main" {
		t.Errorf("Query = %q, want %q", dec.Query, "at=main")
	}

	// An encoded traversal cannot smuggle its way out of the repository.
	for _, path := range []string{
		"/rest/api/1.0/projects/ENG/repos/platform/raw/..%2f..%2fadmin",
		"/rest/api/1.0/projects/ENG/repos/platform/../../admin/users",
		"/rest/api/1.0/projects/ENG/repos/platform/raw/%252e%252e/admin",
		"/rest/api/1.0/projects/ENG/repos/platform\\raw\\main.tf",
	} {
		if dec := e.Evaluate("GET", path, ""); dec.Allowed {
			t.Errorf("Evaluate(GET %s) allowed by rule %s, want denied", path, dec.RuleID)
		}
	}

	// A scoping segment that decodes to another repository is still scoped on
	// what it decodes to, not on the raw bytes.
	if dec := e.Evaluate("GET", "/rest/api/1.0/projects/ENG/repos/plat%66orm/branches", ""); !dec.Allowed {
		t.Fatalf("encoded in-scope repository denied: %s", dec.Reason)
	}
}

func TestBitbucketPolicyHashIsDistinct(t *testing.T) {
	gitLab, gitHub, bitbucket := engine(t).PolicyHash(), gheEngine(t).PolicyHash(), bitbucketEngine(t).PolicyHash()
	if bitbucket == gitLab || bitbucket == gitHub {
		t.Errorf("PolicyHash() = %q collides with another vendor", bitbucket)
	}
}
