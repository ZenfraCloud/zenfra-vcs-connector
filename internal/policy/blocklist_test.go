// ABOUTME: Tests for the opt-in blocklist policy mode: allowlist first, deny table, then allow.
// ABOUTME: Proves the default stays allowlist and that a mode switch changes the policy hash.
package policy

import (
	"strings"
	"testing"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
)

// blocklistEngine builds an unscoped engine in blocklist mode, which is the only
// scope the mode admits.
func blocklistEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(&config.Config{
		Vendor:      config.VendorGitLab,
		AllProjects: true,
		PolicyMode:  config.PolicyModeBlocklist,
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v, want nil", err)
	}
	return e
}

func TestDefaultModeIsAllowlist(t *testing.T) {
	e := engine(t)
	if e.Mode() != config.PolicyModeAllowlist {
		t.Fatalf("Mode() = %q, want %q", e.Mode(), config.PolicyModeAllowlist)
	}
	// An operation no rule describes stays denied: that is the whole default.
	dec := e.Evaluate("GET", "/api/v4/projects/42/pipelines", "")
	if dec.Allowed {
		t.Fatal("Evaluate() allowed an unlisted path in allowlist mode")
	}
}

func TestBlocklistModeAllowsUnlistedOperations(t *testing.T) {
	dec := blocklistEngine(t).Evaluate("GET", "/api/v4/projects/42/pipelines", "per_page=20")
	if !dec.Allowed {
		t.Fatalf("Evaluate() denied %q in blocklist mode: %s", "/api/v4/projects/42/pipelines", dec.Reason)
	}
	if dec.RuleID != RuleUnlisted {
		t.Errorf("RuleID = %q, want %q", dec.RuleID, RuleUnlisted)
	}
	if dec.Origin != OriginPrimary {
		t.Errorf("Origin = %q, want %q", dec.Origin, OriginPrimary)
	}
	if dec.RedirectsTo != "" {
		t.Errorf("RedirectsTo = %q, want no redirect", dec.RedirectsTo)
	}
	if dec.Path != "/api/v4/projects/42/pipelines" || dec.Query != "per_page=20" {
		t.Errorf("Path/Query = %q/%q, want the canonical request", dec.Path, dec.Query)
	}
}

func TestBlocklistModeKeepsAllowlistRuleIdentity(t *testing.T) {
	dec := blocklistEngine(t).Evaluate("GET", "/api/v4/user", "")
	if !dec.Allowed {
		t.Fatalf("Evaluate() denied a compiled rule: %s", dec.Reason)
	}
	if dec.RuleID != "gitlab.user.current" {
		t.Errorf("RuleID = %q, want the compiled rule to answer first", dec.RuleID)
	}
}

func TestBlocklistModeDeniesTheDenyTable(t *testing.T) {
	e := blocklistEngine(t)
	for _, path := range []string{
		"/api/v4/admin/ci/variables",
		"/api/v4/users",
		"/api/v4/users/7/personal_access_tokens",
		"/api/v4/projects/42/variables",
		"/api/v4/projects/42/hooks",
		"/api/v4/projects/42/deploy_tokens",
		"/api/v4/runners",
	} {
		dec := e.Evaluate("GET", path, "")
		if dec.Allowed {
			t.Errorf("Evaluate(GET %s) was allowed, want denied by the deny table", path)
			continue
		}
		if dec.RuleID != RuleDenied {
			t.Errorf("Evaluate(GET %s) RuleID = %q, want %q", path, dec.RuleID, RuleDenied)
		}
	}
}

// The deny table is compared against the raw path, but the upstream decodes it
// before routing — so a percent-encoded deny segment must be caught too, or
// %61dmin reaches /admin. An encoded project path (eng%2Fplatform) decodes to
// several components, which are not path positions of their own and must stay
// allowed even when one of them is a deny-table word.
func TestBlocklistModeDeniesEncodedDenySegments(t *testing.T) {
	e := blocklistEngine(t)
	for _, path := range []string{
		"/api/v4/%61dmin/ci/variables",
		"/api/v4/%75sers",
		"/api/v4/projects/42/%68ooks",
		"/api/v4/ADMIN/ci/variables",
	} {
		dec := e.Evaluate("GET", path, "")
		if dec.Allowed {
			t.Errorf("Evaluate(GET %s) was allowed, want denied by the deny table", path)
			continue
		}
		if dec.RuleID != RuleDenied {
			t.Errorf("Evaluate(GET %s) RuleID = %q, want %q", path, dec.RuleID, RuleDenied)
		}
	}

	// %2F does not buy an exemption. An upstream that decodes before it routes
	// sees these as ordinary path positions, so the table has to see them too.
	for _, path := range []string{
		"/api/v4/admin%2Fci%2Fvariables",
		"/api/v4/projects/1/hooks%2Fnew",
		"/api/v4/users%2F7%2Fpersonal_access_tokens",
		// Not listed: /api/v4/projects/42%2Fvariables matches the compiled
		// gitlab.project.get rule, where %2F is an ordinary project-id character
		// — a reviewed rule, not the deny table's business.
	} {
		dec := e.Evaluate("GET", path, "")
		if dec.Allowed {
			t.Errorf("Evaluate(GET %s) was allowed; %%2F must not skip the deny table", path)
		}
	}

	// Trailing dots and spaces are stripped by Windows-derived stacks, so the
	// table is consulted on the stripped form too.
	for _, path := range []string{"/api/v4/hooks%20", "/api/v4/HOOKS%2E"} {
		if dec := e.Evaluate("GET", path, ""); dec.Allowed {
			t.Errorf("Evaluate(GET %s) was allowed, want denied by the deny table", path)
		}
	}
}

func TestBlocklistModeDeniesDelete(t *testing.T) {
	dec := blocklistEngine(t).Evaluate("DELETE", "/api/v4/projects/42/pipelines/7", "")
	if dec.Allowed {
		t.Fatal("Evaluate(DELETE) was allowed in blocklist mode, want denied")
	}
	if !strings.Contains(dec.Reason, "DELETE") {
		t.Errorf("Reason = %q, want it to name the method", dec.Reason)
	}
}

func TestBlocklistModeStillCanonicalizes(t *testing.T) {
	for _, path := range []string{
		"/api/v4/projects/42/../../admin/users",
		"/api/v4/projects/42/pipelines\x00",
		"https://evil.internal/api/v4/user",
	} {
		if dec := blocklistEngine(t).Evaluate("GET", path, ""); dec.Allowed {
			t.Errorf("Evaluate(GET %q) was allowed, want a canonicalization denial", path)
		}
	}
}

func TestBlocklistModeChangesThePolicyHash(t *testing.T) {
	if allow, block := engine(t).PolicyHash(), blocklistEngine(t).PolicyHash(); allow == block {
		t.Fatal("PolicyHash() is identical across modes; a mode switch must be visible to the gateway")
	}
}
