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
		query       string
		wantRule    string
		wantProject string
	}{
		{method: "GET", path: "/rest/api/1.0/users", query: "limit=1",
			wantRule: "bitbucket.user.current"},
		{method: "GET", path: "/rest/api/1.0/repos", wantRule: "bitbucket.repos.list", wantProject: ""},
		{method: "GET", path: repo, wantRule: "bitbucket.repo.get", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/browse", wantRule: "bitbucket.repo.browse", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/browse/infra/main.tf", wantRule: "bitbucket.repo.browse", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/raw/infra/main.tf", wantRule: "bitbucket.repo.raw", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/branches", wantRule: "bitbucket.branches.list", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/branches/default", wantRule: "bitbucket.branches.default", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/commits", wantRule: "bitbucket.commits.list", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/commits/abc123", wantRule: "bitbucket.commit.get", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/commits/abc123/diff", wantRule: "bitbucket.commit.diff", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/commits/abc123/changes", wantRule: "bitbucket.commit.changes", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/archive", wantRule: "bitbucket.repository.archive", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/pull-requests", wantRule: "bitbucket.pull_requests.list", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/pull-requests/7", wantRule: "bitbucket.pull_request.get", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/pull-requests/7/changes", wantRule: "bitbucket.pull_request.changes", wantProject: "ENG/platform"},
		{method: "GET", path: repo + "/pull-requests/7/diff", wantRule: "bitbucket.pull_request.diff", wantProject: "ENG/platform"},
		{
			method: "GET", path: repo + "/pull-requests/7/comments",
			wantRule: "bitbucket.pull_request.comments.list", wantProject: "ENG/platform",
		},
		{
			method: "POST", path: repo + "/pull-requests/7/comments",
			wantRule: "bitbucket.pull_request.comment.create", wantProject: "ENG/platform",
		},
		{
			method: "PUT", path: repo + "/pull-requests/7/comments/9",
			wantRule: "bitbucket.pull_request.comment.update", wantProject: "ENG/platform",
		},
		{method: "GET", path: repo + "/commits/abc123/builds", wantRule: "bitbucket.build_statuses.list", wantProject: "ENG/platform"},
		{method: "POST", path: repo + "/commits/abc123/builds", wantRule: "bitbucket.build_status.set", wantProject: "ENG/platform"},
	}
	e := bitbucketEngine(t)
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			dec := e.Evaluate(tt.method, tt.path, tt.query)
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
// TestBitbucketUserDirectoryCannotBePaged proves the pinned query on
// bitbucket.user.current is what keeps the rule an identity check: /users is the
// instance's user directory, it captures no project, so --allowed-projects
// cannot scope it and only the query stops it becoming a directory dump.
func TestBitbucketUserDirectoryCannotBePaged(t *testing.T) {
	e := bitbucketEngine(t)
	for _, query := range []string{"", "limit=1000", "limit=1&start=25", "start=0", "limit=2"} {
		if dec := e.Evaluate("GET", "/rest/api/1.0/users", query); dec.Allowed {
			t.Errorf("Evaluate(GET /rest/api/1.0/users?%s) allowed, want denied", query)
		}
	}
}

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
	if dec := e.Evaluate("GET", "/rest/api/1.0/users", "limit=1"); !dec.Allowed {
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
