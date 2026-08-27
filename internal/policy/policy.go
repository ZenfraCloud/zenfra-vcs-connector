// ABOUTME: Compiled default-deny allowlist for tunneled VCS calls: (method, path, purpose) rules.
// ABOUTME: Evaluates canonical requests, scopes them to --allowed-projects, names the matched rule.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// Origin names one of the connector's pinned upstream endpoints. Every origin is
// configured by the operator at startup; nothing on the wire can introduce one.
type Origin string

const (
	// OriginPrimary is --endpoint: the VCS API itself.
	OriginPrimary Origin = "primary"
	// OriginCodeload is --codeload-endpoint: the origin GitHub serves repository
	// archives from, which may be a different host than the API.
	OriginCodeload Origin = "codeload"
)

// Rule is one allowlist entry. The pattern is anchored and matched against the
// canonical path; capture group 1 holds the project identifier when the rule is
// project-scoped.
type Rule struct {
	// ID is the stable identifier reported to the gateway for audit correlation.
	ID string
	// Purpose is the human-readable operation name used in connector logs.
	Purpose string
	Method  string
	// Origin is the pinned endpoint this rule's request is sent to.
	Origin Origin
	// RedirectsTo names the pinned origin a 3xx answer to this rule may be
	// followed to. Empty — the default — means redirects are never followed.
	RedirectsTo Origin

	pattern *regexp.Regexp
	// capturesProject marks rules whose pattern captures a project identifier.
	capturesProject bool
}

// Decision is the outcome of evaluating one request. Path and Query are the exact
// bytes to send upstream and are empty whenever the request was denied.
type Decision struct {
	Allowed bool
	// RuleID and Purpose name the matched rule. They are also set on a denial
	// caused by the method or project scope, so the reason is rule-level.
	RuleID  string
	Purpose string
	Project string
	Method  string
	Path    string
	Query   string
	// Origin is the pinned endpoint the approved request must be sent to, and
	// RedirectsTo the only origin a redirect from it may be followed to.
	Origin      Origin
	RedirectsTo Origin
	// Reason states why a denied request was denied; empty when allowed.
	Reason string
}

// StampHeader records the matched rule on an allowed response so the gateway can
// tie its audit record to the connector's decision.
func (d *Decision) StampHeader(h http.Header) {
	if !d.Allowed || d.RuleID == "" {
		return
	}
	h.Set(tunnel.HeaderPolicyRule, d.RuleID)
}

// Engine enforces one vendor's compiled allowlist plus the operator's project
// scoping. It is immutable after construction and safe for concurrent use.
type Engine struct {
	vendor      config.Vendor
	rules       []Rule
	projects    map[string]struct{}
	allProjects bool
	hash        string
}

// NewEngine compiles the allowlist for the configured vendor.
func NewEngine(cfg *config.Config) (*Engine, error) {
	var rules []Rule
	switch cfg.Vendor {
	case config.VendorGitLab:
		rules = gitLabRules()
	case config.VendorGitHub:
		rules = gitHubRules()
	default:
		return nil, fmt.Errorf("policy: no allowlist for vendor %q, want %q or %q",
			cfg.Vendor, config.VendorGitLab, config.VendorGitHub)
	}
	e := &Engine{
		vendor:      cfg.Vendor,
		rules:       rules,
		projects:    make(map[string]struct{}, len(cfg.AllowedProjects)),
		allProjects: cfg.AllProjects,
	}
	for _, project := range cfg.AllowedProjects {
		e.projects[normalizeProject(project)] = struct{}{}
	}
	e.hash = policyHash(e.vendor, e.rules)
	return e, nil
}

// Rules returns the compiled table. The slice is a copy; the rules themselves are
// read-only.
func (e *Engine) Rules() []Rule {
	return append([]Rule(nil), e.rules...)
}

// PolicyHash fingerprints the compiled rule table. The gateway pins it per
// connector, so an instance running a different allowlist version is refused.
// Operator project scoping is deliberately excluded: instances of one connector
// may be scoped differently and must still admit.
func (e *Engine) PolicyHash() string { return e.hash }

// Evaluate decides one request. It canonicalizes first and matches the canonical
// form, so what was authorized is exactly what the executor sends upstream.
func (e *Engine) Evaluate(method, rawPath, rawQuery string) Decision {
	dec := Decision{Method: strings.ToUpper(strings.TrimSpace(method))}

	path, err := CanonicalizePath(rawPath)
	if err != nil {
		dec.Reason = err.Error()
		return dec
	}
	query, err := CanonicalizeQuery(rawQuery)
	if err != nil {
		dec.Reason = err.Error()
		return dec
	}

	rule, project, matched := e.match(dec.Method, path)
	if !matched {
		if rule == nil {
			dec.Reason = fmt.Sprintf("no rule allows %s %s", dec.Method, path)
			return dec
		}
		// The path is known but this method is not allowed on it.
		dec.RuleID, dec.Purpose = rule.ID, rule.Purpose
		dec.Reason = fmt.Sprintf("method %s is not allowed on %s (rule %s allows %s only)",
			dec.Method, path, rule.ID, rule.Method)
		return dec
	}

	dec.RuleID, dec.Purpose, dec.Project = rule.ID, rule.Purpose, project
	dec.Origin, dec.RedirectsTo = rule.Origin, rule.RedirectsTo
	if !e.projectAllowed(rule, project) {
		dec.Reason = fmt.Sprintf("project %q is outside --allowed-projects (rule %s)",
			project, rule.ID)
		return dec
	}

	dec.Allowed, dec.Path, dec.Query = true, path, query
	return dec
}

// match finds the rule allowing method on path. When no rule allows the method but
// one matches the path, that rule is returned with matched=false so the denial can
// say which operation was refused.
func (e *Engine) match(method, path string) (rule *Rule, project string, matched bool) {
	var pathOnly *Rule
	for i := range e.rules {
		candidate := &e.rules[i]
		groups := candidate.pattern.FindStringSubmatch(path)
		if groups == nil {
			continue
		}
		if candidate.Method != method {
			if pathOnly == nil {
				pathOnly = candidate
			}
			continue
		}
		if candidate.capturesProject && len(groups) > 1 {
			project = decodeProject(groups[1])
		}
		return candidate, project, true
	}
	return pathOnly, "", false
}

// projectAllowed applies --allowed-projects. Project-independent rules (current
// user, project list) are never scoped: without them verify and discovery break.
func (e *Engine) projectAllowed(rule *Rule, project string) bool {
	if e.allProjects || !rule.capturesProject {
		return true
	}
	_, ok := e.projects[normalizeProject(project)]
	return ok
}

// decodeProject turns the captured path segment into the project identifier a
// human configured: a numeric ID, or a namespace path with real slashes.
func decodeProject(segment string) string {
	decoded, err := url.PathUnescape(segment)
	if err != nil {
		// Unreachable: canonicalization already unescaped every segment.
		return segment
	}
	return decoded
}

// normalizeProject makes scope comparison case-insensitive; GitLab namespaces are
// not case-sensitive in practice and operators type them either way.
func normalizeProject(project string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(project), "/"))
}

// policyHash digests the rule table so any change to the allowlist produces a new
// fingerprint.
func policyHash(vendor config.Vendor, rules []Rule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "vendor=%s\n", vendor)
	for _, rule := range rules {
		fmt.Fprintf(&b, "%s %s %s %s %s\n",
			rule.Method, rule.pattern.String(), rule.ID, rule.Origin, rule.RedirectsTo)
	}
	digest := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(digest[:])
}

// project matches one canonical path segment, which may hold an encoded namespace
// path (eng%2Fplatform) or a numeric ID.
const project = `([^/]+)`

// gitLabRules is the compiled GitLab v4 surface Zenfra needs. Everything absent
// here is denied, including every write beyond MR comments and commit statuses.
// Smart-HTTP git endpoints are deliberately absent: archives travel the bulk lane.
func gitLabRules() []Rule {
	specs := []struct {
		id, purpose, method, pattern string
	}{
		{"gitlab.user.current", "Get Current User", "GET", `^/api/v4/user$`},
		// ponytail: the project list exposes names outside --allowed-projects, which
		// repo discovery needs. Response filtering, if ever wanted, belongs in the
		// discovery service, not the path allowlist.
		{"gitlab.projects.list", "List Projects", "GET", `^/api/v4/projects$`},
		{"gitlab.project.get", "Get Project", "GET", `^/api/v4/projects/` + project + `$`},
		{
			"gitlab.repository.tree", "List Repository Tree", "GET",
			`^/api/v4/projects/` + project + `/repository/tree$`,
		},
		{
			"gitlab.branches.list", "List Branches", "GET",
			`^/api/v4/projects/` + project + `/repository/branches$`,
		},
		{
			"gitlab.branch.get", "Get Branch", "GET",
			`^/api/v4/projects/` + project + `/repository/branches/[^/]+$`,
		},
		{
			"gitlab.commits.list", "List Commits", "GET",
			`^/api/v4/projects/` + project + `/repository/commits$`,
		},
		{
			"gitlab.commit.get", "Get Commit", "GET",
			`^/api/v4/projects/` + project + `/repository/commits/[^/]+$`,
		},
		{
			"gitlab.commit.diff", "Get Commit Diff", "GET",
			`^/api/v4/projects/` + project + `/repository/commits/[^/]+/diff$`,
		},
		{
			"gitlab.commit.statuses.list", "List Commit Statuses", "GET",
			`^/api/v4/projects/` + project + `/repository/commits/[^/]+/statuses$`,
		},
		{
			"gitlab.repository.compare", "Compare Refs", "GET",
			`^/api/v4/projects/` + project + `/repository/compare$`,
		},
		{
			"gitlab.repository.file.raw", "Get Raw File", "GET",
			`^/api/v4/projects/` + project + `/repository/files/[^/]+/raw$`,
		},
		{
			"gitlab.repository.archive", "Download Repository Archive", "GET",
			`^/api/v4/projects/` + project + `/repository/archive(\.tar\.gz|\.tar\.bz2|\.tar|\.zip)?$`,
		},
		{
			"gitlab.merge_requests.list", "List Merge Requests", "GET",
			`^/api/v4/projects/` + project + `/merge_requests$`,
		},
		{
			"gitlab.merge_request.get", "Get Merge Request", "GET",
			`^/api/v4/projects/` + project + `/merge_requests/[0-9]+$`,
		},
		{
			"gitlab.merge_request.changes", "Get Merge Request Changes", "GET",
			`^/api/v4/projects/` + project + `/merge_requests/[0-9]+/changes$`,
		},
		{
			"gitlab.merge_request.notes.list", "List Merge Request Comments", "GET",
			`^/api/v4/projects/` + project + `/merge_requests/[0-9]+/notes$`,
		},
		{
			"gitlab.merge_request.notes.create", "Comment on Merge Request", "POST",
			`^/api/v4/projects/` + project + `/merge_requests/[0-9]+/notes$`,
		},
		{
			"gitlab.merge_request.notes.update", "Update Merge Request Comment", "PUT",
			`^/api/v4/projects/` + project + `/merge_requests/[0-9]+/notes/[0-9]+$`,
		},
		{
			"gitlab.commit.status.set", "Set Commit Status", "POST",
			`^/api/v4/projects/` + project + `/statuses/[^/]+$`,
		},
	}

	// Every GitLab rule is served by the primary endpoint and follows no
	// redirect, so the table carries neither column.
	gitLab := make([]ruleSpec, 0, len(specs))
	for _, spec := range specs {
		gitLab = append(gitLab, ruleSpec{
			id: spec.id, purpose: spec.purpose, method: spec.method, pattern: spec.pattern,
		})
	}
	return compile(gitLab)
}

// ruleSpec is the source form of a rule: origins default to primary and a rule
// follows no redirect unless it says so.
type ruleSpec struct {
	id, purpose, method, pattern string
	origin, redirectsTo          Origin
}

// compile turns rule specs into matchable rules. A pattern's first capture group
// is the project identifier, so a rule with no group is project-independent.
func compile(specs []ruleSpec) []Rule {
	rules := make([]Rule, 0, len(specs))
	for _, spec := range specs {
		// MustCompile is safe: the patterns are compile-time constants covered by tests.
		pattern := regexp.MustCompile(spec.pattern)
		origin := spec.origin
		if origin == "" {
			origin = OriginPrimary
		}
		rules = append(rules, Rule{
			ID:              spec.id,
			Purpose:         spec.purpose,
			Method:          spec.method,
			Origin:          origin,
			RedirectsTo:     spec.redirectsTo,
			pattern:         pattern,
			capturesProject: pattern.NumSubexp() > 0,
		})
	}
	return rules
}
