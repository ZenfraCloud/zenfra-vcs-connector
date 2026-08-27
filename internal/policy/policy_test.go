// ABOUTME: Tests for the compiled GitLab allowlist: rule coverage, default-deny, project scoping.
// ABOUTME: Also proves the matched rule ID travels back to the gateway for audit correlation.
package policy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// engine builds an engine scoped to the given projects; empty means all-projects.
func engine(t *testing.T, projects ...string) *Engine {
	t.Helper()
	cfg := &config.Config{
		Vendor:          config.VendorGitLab,
		AllowedProjects: projects,
		AllProjects:     len(projects) == 0,
	}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v, want nil", err)
	}
	return e
}

func TestNewEngineRejectsUnsupportedVendor(t *testing.T) {
	_, err := NewEngine(&config.Config{Vendor: "github", AllProjects: true})
	if err == nil {
		t.Fatal("NewEngine() error = nil, want an unsupported-vendor error")
	}
	if !strings.Contains(err.Error(), "github") {
		t.Errorf("NewEngine() error = %q, want it to name the vendor", err)
	}
}

func TestAllowlistCoversTheGitLabSurface(t *testing.T) {
	tests := []struct {
		method      string
		path        string
		wantRule    string
		wantProject string
	}{
		{"GET", "/api/v4/user", "gitlab.user.current", ""},
		{"GET", "/api/v4/projects", "gitlab.projects.list", ""},
		{"GET", "/api/v4/projects/42", "gitlab.project.get", "42"},
		{"GET", "/api/v4/projects/eng%2Fplatform", "gitlab.project.get", "eng/platform"},
		{"GET", "/api/v4/projects/42/repository/tree", "gitlab.repository.tree", "42"},
		{"GET", "/api/v4/projects/42/repository/branches", "gitlab.branches.list", "42"},
		{"GET", "/api/v4/projects/42/repository/branches/feature%2Flogin", "gitlab.branch.get", "42"},
		{"GET", "/api/v4/projects/42/repository/commits", "gitlab.commits.list", "42"},
		{"GET", "/api/v4/projects/42/repository/commits/abc123", "gitlab.commit.get", "42"},
		{"GET", "/api/v4/projects/42/repository/commits/abc123/diff", "gitlab.commit.diff", "42"},
		{"GET", "/api/v4/projects/42/repository/commits/abc123/statuses", "gitlab.commit.statuses.list", "42"},
		{"GET", "/api/v4/projects/42/repository/compare", "gitlab.repository.compare", "42"},
		{"GET", "/api/v4/projects/42/repository/files/main.tf/raw", "gitlab.repository.file.raw", "42"},
		{"GET", "/api/v4/projects/42/repository/archive.tar.gz", "gitlab.repository.archive", "42"},
		{"GET", "/api/v4/projects/42/repository/archive.zip", "gitlab.repository.archive", "42"},
		{"GET", "/api/v4/projects/42/repository/archive", "gitlab.repository.archive", "42"},
		{"GET", "/api/v4/projects/42/merge_requests", "gitlab.merge_requests.list", "42"},
		{"GET", "/api/v4/projects/42/merge_requests/7", "gitlab.merge_request.get", "42"},
		{"GET", "/api/v4/projects/42/merge_requests/7/changes", "gitlab.merge_request.changes", "42"},
		{"GET", "/api/v4/projects/42/merge_requests/7/notes", "gitlab.merge_request.notes.list", "42"},
		{"POST", "/api/v4/projects/42/merge_requests/7/notes", "gitlab.merge_request.notes.create", "42"},
		{"PUT", "/api/v4/projects/42/merge_requests/7/notes/9", "gitlab.merge_request.notes.update", "42"},
		{"POST", "/api/v4/projects/42/statuses/abc123", "gitlab.commit.status.set", "42"},
	}
	e := engine(t)
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
				t.Errorf("Purpose is empty for rule %q, want a human-readable name", dec.RuleID)
			}
			if dec.Project != tt.wantProject {
				t.Errorf("Project = %q, want %q", dec.Project, tt.wantProject)
			}
			if dec.Path != tt.path {
				t.Errorf("Path = %q, want the canonical path %q sent upstream verbatim", dec.Path, tt.path)
			}
		})
	}
}

// TestEveryRuleIsCovered fails when a rule is added without an allow test above,
// so the compiled table can never grow an unexercised entry.
func TestEveryRuleIsCovered(t *testing.T) {
	e := engine(t)
	covered := map[string]bool{}
	for _, tt := range []string{
		"gitlab.user.current", "gitlab.projects.list", "gitlab.project.get",
		"gitlab.repository.tree", "gitlab.branches.list", "gitlab.branch.get",
		"gitlab.commits.list", "gitlab.commit.get", "gitlab.commit.diff",
		"gitlab.commit.statuses.list", "gitlab.repository.compare",
		"gitlab.repository.file.raw", "gitlab.repository.archive",
		"gitlab.merge_requests.list", "gitlab.merge_request.get",
		"gitlab.merge_request.changes", "gitlab.merge_request.notes.list",
		"gitlab.merge_request.notes.create", "gitlab.merge_request.notes.update",
		"gitlab.commit.status.set",
	} {
		covered[tt] = true
	}
	for _, rule := range e.Rules() {
		if !covered[rule.ID] {
			t.Errorf("rule %q (%s) has no allow test in TestAllowlistCoversTheGitLabSurface", rule.ID, rule.Purpose)
		}
	}
	if len(e.Rules()) != len(covered) {
		t.Errorf("rule count = %d, covered = %d", len(e.Rules()), len(covered))
	}
}

func TestEvaluateDeniesEverythingElse(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		wantReason string
	}{
		{"admin api", "GET", "/api/v4/admin/users", "no rule"},
		{"user list", "GET", "/api/v4/users", "no rule"},
		{"project variables", "GET", "/api/v4/projects/42/variables", "no rule"},
		{"project hooks", "POST", "/api/v4/projects/42/hooks", "no rule"},
		{"project members", "GET", "/api/v4/projects/42/members", "no rule"},
		{"runners", "GET", "/api/v4/runners", "no rule"},
		{"personal access tokens", "GET", "/api/v4/personal_access_tokens", "no rule"},
		{"graphql", "POST", "/api/graphql", "no rule"},
		{"delete project", "DELETE", "/api/v4/projects/42", "method"},
		{"create project", "POST", "/api/v4/projects", "method"},
		{"write file", "PUT", "/api/v4/projects/42/repository/files/main.tf/raw", "method"},
		{"delete note", "DELETE", "/api/v4/projects/42/merge_requests/7/notes/9", "method"},
		{"non numeric mr iid", "GET", "/api/v4/projects/42/merge_requests/abc", "no rule"},
		{"traversal", "GET", "/api/v4/projects/42/repository/%2e%2e/%2e%2e/admin", "dot segment"},
		{"absolute url", "GET", "https://gitlab.evil/api/v4/user", "must start with"},
	}
	e := engine(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.Evaluate(tt.method, tt.path, "")
			if dec.Allowed {
				t.Fatalf("Evaluate(%s %s) allowed via %q, want denied", tt.method, tt.path, dec.RuleID)
			}
			if !strings.Contains(dec.Reason, tt.wantReason) {
				t.Errorf("Reason = %q, want it to mention %q", dec.Reason, tt.wantReason)
			}
			if dec.Path != "" {
				t.Errorf("Path = %q, want empty so a denied request can never be sent", dec.Path)
			}
		})
	}
}

// TestDenyReasonCarriesRuleLevelDetail proves a denial says which rule was
// involved, not just "denied".
func TestDenyReasonCarriesRuleLevelDetail(t *testing.T) {
	e := engine(t, "42")

	methodMismatch := e.Evaluate("DELETE", "/api/v4/projects/42", "")
	if methodMismatch.Allowed {
		t.Fatal("DELETE /api/v4/projects/42 allowed, want denied")
	}
	if methodMismatch.RuleID != "gitlab.project.get" {
		t.Errorf("RuleID = %q, want the path-matching rule named on a method denial", methodMismatch.RuleID)
	}
	if !strings.Contains(methodMismatch.Reason, "DELETE") {
		t.Errorf("Reason = %q, want it to name the rejected method", methodMismatch.Reason)
	}

	outOfScope := e.Evaluate("GET", "/api/v4/projects/99/repository/tree", "")
	if outOfScope.Allowed {
		t.Fatal("project 99 allowed, want denied by scoping")
	}
	if outOfScope.RuleID != "gitlab.repository.tree" {
		t.Errorf("RuleID = %q, want the matched rule named on a scoping denial", outOfScope.RuleID)
	}
	if outOfScope.Project != "99" {
		t.Errorf("Project = %q, want the rejected project named", outOfScope.Project)
	}
	if !strings.Contains(outOfScope.Reason, "99") || !strings.Contains(outOfScope.Reason, "allowed-projects") {
		t.Errorf("Reason = %q, want it to name the project and the scoping flag", outOfScope.Reason)
	}

	noRule := e.Evaluate("GET", "/api/v4/admin/users", "")
	if !strings.Contains(noRule.Reason, "GET") || !strings.Contains(noRule.Reason, "/api/v4/admin/users") {
		t.Errorf("Reason = %q, want it to name the method and path", noRule.Reason)
	}
	if noRule.RuleID != "" {
		t.Errorf("RuleID = %q, want empty when nothing matched", noRule.RuleID)
	}
}

func TestProjectScoping(t *testing.T) {
	tests := []struct {
		name        string
		projects    []string
		path        string
		wantAllowed bool
	}{
		{"numeric id in scope", []string{"42"}, "/api/v4/projects/42/repository/tree", true},
		{"numeric id out of scope", []string{"42"}, "/api/v4/projects/43/repository/tree", false},
		{"path in scope", []string{"eng/platform"}, "/api/v4/projects/eng%2Fplatform/repository/tree", true},
		{"path out of scope", []string{"eng/platform"}, "/api/v4/projects/eng%2Fother/repository/tree", false},
		{"path case insensitive", []string{"eng/platform"}, "/api/v4/projects/Eng%2FPlatform/repository/tree", true},
		{"configured case insensitive", []string{"Eng/Platform"}, "/api/v4/projects/eng%2Fplatform/repository/tree", true},
		{"multiple entries", []string{"42", "eng/platform"}, "/api/v4/projects/eng%2Fplatform", true},
		{"all projects", nil, "/api/v4/projects/anything%2Fgoes/repository/tree", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := engine(t, tt.projects...).Evaluate("GET", tt.path, "")
			if dec.Allowed != tt.wantAllowed {
				t.Fatalf("Evaluate(GET %s) allowed = %v (%s), want %v",
					tt.path, dec.Allowed, dec.Reason, tt.wantAllowed)
			}
		})
	}
}

// TestProjectIndependentRulesIgnoreScoping keeps verify and discovery working on a
// scoped connector: neither call names a project.
func TestProjectIndependentRulesIgnoreScoping(t *testing.T) {
	e := engine(t, "42")
	for _, path := range []string{"/api/v4/user", "/api/v4/projects"} {
		if dec := e.Evaluate("GET", path, ""); !dec.Allowed {
			t.Errorf("Evaluate(GET %s) denied: %s", path, dec.Reason)
		}
	}
}

func TestEvaluateCanonicalizesQuery(t *testing.T) {
	e := engine(t)

	dec := e.Evaluate("GET", "/api/v4/projects/42/repository/tree", "ref=main&path=src%2Fmain.tf")
	if !dec.Allowed {
		t.Fatalf("Evaluate denied: %s", dec.Reason)
	}
	if dec.Query != "ref=main&path=src%2Fmain.tf" {
		t.Errorf("Query = %q, want it passed through canonicalized", dec.Query)
	}

	bad := e.Evaluate("GET", "/api/v4/projects/42/repository/tree", "ref=ma\nin")
	if bad.Allowed {
		t.Fatal("query with a control character allowed, want denied")
	}
	if !strings.Contains(bad.Reason, "query") {
		t.Errorf("Reason = %q, want it to name the query", bad.Reason)
	}
}

func TestEvaluateNormalizesMethodCase(t *testing.T) {
	dec := engine(t).Evaluate("get", "/api/v4/user", "")
	if !dec.Allowed {
		t.Fatalf("lowercase method denied: %s", dec.Reason)
	}
	if dec.Method != "GET" {
		t.Errorf("Method = %q, want %q", dec.Method, "GET")
	}
}

func TestPolicyHashIsStableAndScopeIndependent(t *testing.T) {
	first := engine(t, "42").PolicyHash()
	if first == "" {
		t.Fatal("PolicyHash() is empty")
	}
	if len(first) != 64 {
		t.Errorf("PolicyHash() = %q, want a 64-char sha256 hex digest", first)
	}
	if second := engine(t, "42").PolicyHash(); second != first {
		t.Errorf("PolicyHash() = %q then %q, want it stable", first, second)
	}
	// The hash pins the compiled rule table, not operator scoping: two instances of
	// one connector with different project lists must still admit to the gateway.
	if scoped := engine(t, "eng/platform").PolicyHash(); scoped != first {
		t.Errorf("PolicyHash() changed with --allowed-projects: %q vs %q", first, scoped)
	}
}

// TestRuleIDReachesTheGateway proves the matched rule rides the response head over
// the wire, which is how a gateway audit record correlates to a connector decision.
func TestRuleIDReachesTheGateway(t *testing.T) {
	dec := engine(t).Evaluate("GET", "/api/v4/projects/42/repository/commits/abc123", "")
	if !dec.Allowed {
		t.Fatalf("Evaluate denied: %s", dec.Reason)
	}

	header := http.Header{"Content-Type": {"application/json"}}
	dec.StampHeader(header)

	// Build the response head the way the executor will, then read it back as the
	// gateway does.
	head := &tunnel.HTTPResponseHead{Status: 200, Headers: map[string]*tunnel.HeaderValues{}}
	for name, values := range header {
		head.Headers[name] = &tunnel.HeaderValues{Values: values}
	}
	encoded, err := tunnel.Encode(&tunnel.Envelope{
		RequestId: "req-1",
		Msg:       &tunnel.Envelope_HttpResponseHead{HttpResponseHead: head},
	})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	env, err := tunnel.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	got := env.GetHttpResponseHead().GetHeaders()[tunnel.HeaderPolicyRule].GetValues()
	if len(got) != 1 || got[0] != "gitlab.commit.get" {
		t.Errorf("%s = %v, want [gitlab.commit.get]", tunnel.HeaderPolicyRule, got)
	}
}

func TestStampHeaderSkipsDeniedDecisions(t *testing.T) {
	dec := engine(t).Evaluate("GET", "/api/v4/admin/users", "")
	header := http.Header{}
	dec.StampHeader(header)
	if got := header.Get(tunnel.HeaderPolicyRule); got != "" {
		t.Errorf("%s = %q on a denied decision, want it absent", tunnel.HeaderPolicyRule, got)
	}
}
