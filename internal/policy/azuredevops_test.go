// ABOUTME: Tests for the compiled Azure DevOps Server allowlist (collection-relative /_apis).
// ABOUTME: Covers the endpoint surface, project/repo scoping, case-insensitive routes and canonicalization.
package policy

import (
	"strings"
	"testing"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
)

// azureDevOpsEngine builds an Azure DevOps engine scoped to the given
// Project/repo pairs; empty means all-projects.
func azureDevOpsEngine(t *testing.T, repos ...string) *Engine {
	t.Helper()
	cfg := &config.Config{
		Vendor:          config.VendorAzureDevOps,
		AllowedProjects: repos,
		AllProjects:     len(repos) == 0,
	}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v, want nil", err)
	}
	return e
}

func TestAllowlistCoversTheAzureDevOpsSurface(t *testing.T) {
	const repo = "/Platform/_apis/git/repositories/infra"
	tests := []struct {
		method      string
		path        string
		wantRule    string
		wantProject string
	}{
		{"GET", "/_apis/connectionData", "azure_devops.connection_data", ""},
		{"GET", "/_apis/git/repositories", "azure_devops.repos.list", ""},
		{"GET", repo, "azure_devops.repo.get", "Platform/infra"},
		{"GET", repo + "/items", "azure_devops.repository.items", "Platform/infra"},
		{"GET", repo + "/refs", "azure_devops.refs.list", "Platform/infra"},
		{"GET", repo + "/commits", "azure_devops.commits.list", "Platform/infra"},
		{"GET", repo + "/commits/abc123", "azure_devops.commit.get", "Platform/infra"},
		{"GET", repo + "/commits/abc123/changes", "azure_devops.commit.changes", "Platform/infra"},
		{
			"GET", repo + "/commits/abc123/statuses",
			"azure_devops.commit.statuses.list", "Platform/infra",
		},
		{
			"POST", repo + "/commits/abc123/statuses",
			"azure_devops.commit.status.set", "Platform/infra",
		},
		{"GET", repo + "/pullrequests", "azure_devops.pull_requests.list", "Platform/infra"},
		{"GET", repo + "/pullrequests/7", "azure_devops.pull_request.get", "Platform/infra"},
		{
			"GET", repo + "/pullrequests/7/threads",
			"azure_devops.pull_request.threads.list", "Platform/infra",
		},
		{
			"POST", repo + "/pullrequests/7/threads",
			"azure_devops.pull_request.thread.create", "Platform/infra",
		},
		{
			"PATCH", repo + "/pullrequests/7/threads/3/comments/9",
			"azure_devops.pull_request.comment.update", "Platform/infra",
		},
	}
	e := azureDevOpsEngine(t)
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			dec := e.Evaluate(tt.method, tt.path, "api-version=6.0")
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
			// Archives come from the collection host itself, so there is no second
			// origin and nothing may follow a redirect.
			if dec.Origin != OriginPrimary {
				t.Errorf("Origin = %q, want %q", dec.Origin, OriginPrimary)
			}
			if dec.RedirectsTo != "" {
				t.Errorf("RedirectsTo = %q, want empty", dec.RedirectsTo)
			}
		})
	}
}

// Azure DevOps routes are case-insensitive, so /pullRequests and /pullrequests
// are the same resource. Denying one of them would deny a call the upstream
// would have served while stopping nothing.
func TestAzureDevOpsRoutesAreCaseInsensitive(t *testing.T) {
	e := azureDevOpsEngine(t, "Platform/infra")
	for _, path := range []string{
		"/Platform/_apis/git/repositories/infra/pullRequests/7/threads",
		"/Platform/_APIS/git/Repositories/infra/pullRequests/7/Threads",
		"/_apis/connectiondata",
	} {
		if dec := e.Evaluate("GET", path, ""); !dec.Allowed {
			t.Errorf("Evaluate(GET %s) denied: %s", path, dec.Reason)
		}
	}
}

func TestAzureDevOpsAllowlistDeniesEverythingElse(t *testing.T) {
	const repo = "/Platform/_apis/git/repositories/infra"
	denied := []struct{ method, path string }{
		{"DELETE", repo},
		{"POST", "/Platform/_apis/git/repositories"},
		{"POST", repo + "/pushes"},
		{"POST", repo + "/pullrequests"},
		{"PATCH", repo + "/pullrequests/7"},
		{"POST", repo + "/pullrequests/7/reviewers"},
		// Service connections hold customer cloud credentials.
		{"GET", "/Platform/_apis/serviceendpoint/endpoints"},
		{"GET", "/Platform/_apis/distributedtask/variablegroups"},
		{"GET", "/Platform/_apis/build/builds"},
		{"GET", "/_apis/graph/users"},
		{"GET", "/_apis/tokens/pats"},
		// Smart-HTTP git: archives travel the bulk lane, not git protocol.
		{"GET", "/Platform/_git/infra/info/refs"},
	}
	e := azureDevOpsEngine(t)
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

// Azure DevOps splits repository identity across the project and repository
// segments; scoping compares the "Project/repo" string an operator configures.
func TestAzureDevOpsProjectScopingJoinsProjectAndRepository(t *testing.T) {
	e := azureDevOpsEngine(t, "Platform/infra")

	if dec := e.Evaluate("GET", "/Platform/_apis/git/repositories/infra/refs", ""); !dec.Allowed {
		t.Fatalf("in-scope repository denied: %s", dec.Reason)
	}
	// A different repository in the same project is a different scope.
	dec := e.Evaluate("GET", "/Platform/_apis/git/repositories/secrets/refs", "")
	if dec.Allowed {
		t.Fatal("out-of-scope repository allowed, want denied")
	}
	if !strings.Contains(dec.Reason, "Platform/secrets") {
		t.Errorf("Reason = %q, want it to name the out-of-scope repository", dec.Reason)
	}
	// Same repository name under another project is also out of scope.
	if dec := e.Evaluate("GET", "/Other/_apis/git/repositories/infra/refs", ""); dec.Allowed {
		t.Fatal("out-of-scope project allowed, want denied")
	}
	// The identity call is repository-independent and must stay reachable.
	if dec := e.Evaluate("GET", "/_apis/connectionData", ""); !dec.Allowed {
		t.Fatalf("repository-independent rule denied: %s", dec.Reason)
	}
}

// Canonicalization runs before matching, so what the allowlist approved is
// exactly the bytes the executor sends.
func TestAzureDevOpsCanonicalizationBeforeMatch(t *testing.T) {
	// Azure DevOps project names may contain spaces, which arrive percent-encoded.
	e := azureDevOpsEngine(t, "My Project/infra")

	dec := e.Evaluate("GET", "/My%20Project/_apis/git/repositories/infra/items",
		"path=%2Fmain.tf&api-version=6.0")
	if !dec.Allowed {
		t.Fatalf("encoded project denied: %s", dec.Reason)
	}
	if want := "/My%20Project/_apis/git/repositories/infra/items"; dec.Path != want {
		t.Errorf("Path = %q, want %q", dec.Path, want)
	}
	if want := "path=%2Fmain.tf&api-version=6.0"; dec.Query != want {
		t.Errorf("Query = %q, want %q", dec.Query, want)
	}
	// Lower-case escape hex is uppercased; structure is never rewritten.
	if dec := e.Evaluate("GET", "/My%20project/_apis/git/repositories/infra/refs", ""); !dec.Allowed {
		t.Fatalf("encoded project denied on case: %s", dec.Reason)
	}

	// An encoded traversal cannot smuggle its way out of the repository.
	for _, path := range []string{
		"/My%20Project/_apis/git/repositories/infra/items/..%2f..%2f_apis%2ftokens",
		"/My%20Project/_apis/git/repositories/infra/../../_apis/graph/users",
		"/My%20Project/_apis/git/repositories/infra/items/%252e%252e/admin",
		"/My%20Project/_apis/git/repositories/infra\\items",
	} {
		if dec := e.Evaluate("GET", path, ""); dec.Allowed {
			t.Errorf("Evaluate(GET %s) allowed by rule %s, want denied", path, dec.RuleID)
		}
	}
}

func TestAzureDevOpsPolicyHashIsDistinct(t *testing.T) {
	hashes := map[string]string{
		"gitlab":       engine(t).PolicyHash(),
		"github":       gheEngine(t).PolicyHash(),
		"bitbucket":    bitbucketEngine(t).PolicyHash(),
		"azure_devops": azureDevOpsEngine(t).PolicyHash(),
	}
	for vendor, hash := range hashes {
		if vendor == "azure_devops" {
			continue
		}
		if hash == hashes["azure_devops"] {
			t.Errorf("PolicyHash() collides with %s", vendor)
		}
	}
}
