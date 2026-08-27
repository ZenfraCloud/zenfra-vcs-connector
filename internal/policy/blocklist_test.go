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
