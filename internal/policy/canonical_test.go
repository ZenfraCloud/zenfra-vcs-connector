// ABOUTME: Tests for request path/query canonicalization — the pre-match trust boundary.
// ABOUTME: Every rejection case here is an attack shape the allowlist must never see.
package policy

import (
	"strings"
	"testing"
)

func TestCanonicalizePathAccepts(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"simple", "/api/v4/user", "/api/v4/user"},
		{"numeric project", "/api/v4/projects/42/repository/tree", "/api/v4/projects/42/repository/tree"},
		{
			"encoded project path",
			"/api/v4/projects/eng%2Fplatform/repository/archive.tar.gz",
			"/api/v4/projects/eng%2Fplatform/repository/archive.tar.gz",
		},
		{
			"escape hex uppercased",
			"/api/v4/projects/eng%2fplatform",
			"/api/v4/projects/eng%2Fplatform",
		},
		{
			"encoded branch name",
			"/api/v4/projects/42/repository/branches/feature%2Flogin",
			"/api/v4/projects/42/repository/branches/feature%2Flogin",
		},
		{"dot in filename", "/api/v4/projects/42/repository/files/main.tf/raw", "/api/v4/projects/42/repository/files/main.tf/raw"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalizePath(tt.raw)
			if err != nil {
				t.Fatalf("CanonicalizePath(%q) error = %v, want nil", tt.raw, err)
			}
			if got != tt.want {
				t.Errorf("CanonicalizePath(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCanonicalizePathRejects(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		// wantReason is a substring of the error naming why it was rejected.
		wantReason string
	}{
		{"empty", "", "empty"},
		{"relative", "api/v4/user", "must start with"},
		{"scheme relative", "//gitlab.evil/api/v4/user", "empty segment"},
		{"absolute url", "https://gitlab.evil/api/v4/user", "must start with"},
		{"absolute url after slash", "/https://gitlab.evil/api/v4/user", "absolute URL"},
		{"dot segment", "/api/v4/./user", "dot segment"},
		{"traversal", "/api/v4/../admin/users", "dot segment"},
		{"encoded traversal", "/api/v4/%2e%2e/admin/users", "dot segment"},
		{"encoded traversal uppercase", "/api/v4/%2E%2E/admin/users", "dot segment"},
		{"traversal inside encoded segment", "/api/v4/projects/eng%2F..%2Fother", "dot segment"},
		// Tomcat/Jetty strip ;path-parameters before resolving dot segments, so
		// "..;" would match a rule verbatim and traverse upstream.
		{"path parameter traversal", "/rest/api/1.0/projects/P/repos/r/browse/..;/..;/admin", "path parameter"},
		{"encoded path parameter traversal", "/rest/api/1.0/projects/P/repos/r/browse/%2E%2E;/admin", "path parameter"},
		// %3B survives the raw ; check byte-for-byte; any hop that decodes it before
		// the upstream's path-parameter parser gets the "..;" back.
		{"percent-encoded path parameter", "/rest/api/1.0/projects/P/repos/r/browse/..%3B/admin", "or ;"},
		{"fully encoded path parameter", "/rest/api/1.0/projects/P/repos/r/browse/%2E%2E%3B/admin", "or ;"},
		{"trailing space traversal", "/api/v4/..%20/admin/users", "dot segment"},
		{"trailing dot traversal", "/api/v4/...%2E/admin/users", "dot segment"},
		{"double encoding", "/api/v4/%252e%252e/admin/users", "double-encoded"},
		{"double encoded slash", "/api/v4/projects/eng%252Fplatform", "double-encoded"},
		{"backslash", "/api/v4\\admin\\users", "backslash"},
		{"encoded backslash", "/api/v4/%5cadmin", "backslash"},
		{"empty segment", "/api/v4//user", "empty segment"},
		{"trailing slash", "/api/v4/user/", "empty segment"},
		{"empty segment inside encoded", "/api/v4/projects/eng%2F%2Fother", "empty segment"},
		{"query in path", "/api/v4/user?private_token=x", "query"},
		{"fragment", "/api/v4/user#frag", "fragment"},
		{"userinfo", "/api/v4/user@gitlab.evil", "@"},
		{"encoded userinfo", "/api/v4/user%40gitlab.evil", "@"},
		{"encoded query", "/api/v4/user%3Fprivate_token=x", "query"},
		{"encoded fragment", "/api/v4/user%23frag", "fragment"},
		{"control character", "/api/v4/us\x00er", "control character"},
		{"newline", "/api/v4/user\nHost: evil", "control character"},
		{"encoded nul", "/api/v4/%00user", "control character"},
		{"encoded newline", "/api/v4/user%0Ax", "control character"},
		{"del character", "/api/v4/us\x7fer", "control character"},
		{"truncated escape", "/api/v4/user%", "percent-encoding"},
		{"invalid escape", "/api/v4/user%zz", "percent-encoding"},
		{"too long", "/api/v4/" + strings.Repeat("a", maxPathBytes), "too long"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalizePath(tt.raw)
			if err == nil {
				t.Fatalf("CanonicalizePath(%q) = %q, want error", tt.raw, got)
			}
			if !strings.Contains(err.Error(), tt.wantReason) {
				t.Errorf("CanonicalizePath(%q) error = %q, want it to mention %q", tt.raw, err, tt.wantReason)
			}
			if got != "" {
				t.Errorf("CanonicalizePath(%q) = %q, want empty path on rejection", tt.raw, got)
			}
		})
	}
}

func TestCanonicalizeQuery(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr string
	}{
		{name: "empty", raw: "", want: ""},
		{name: "simple", raw: "ref=main&per_page=100", want: "ref=main&per_page=100"},
		{name: "encoded value", raw: "path=src%2Fmain.tf", want: "path=src%2Fmain.tf"},
		// A percent sign in a value is legitimately double-encoded; the query never
		// participates in routing, so it is not a traversal vector.
		{name: "encoded percent value", raw: "search=50%25", want: "search=50%25"},
		{name: "leading question mark", raw: "?ref=main", wantErr: "must not start with"},
		{name: "fragment", raw: "ref=main#frag", wantErr: "fragment"},
		{name: "control character", raw: "ref=ma\nin", wantErr: "control character"},
		{name: "invalid escape", raw: "ref=%zz", wantErr: "percent-encoding"},
		{name: "too long", raw: "ref=" + strings.Repeat("a", maxQueryBytes), wantErr: "too long"},
		// GitLab honours ?private_token= as authentication, so a credential in the
		// query would ride the connector's upstream session past the inbound
		// credential-header refusal.
		{name: "gitlab private token", raw: "private_token=glpat-x", wantErr: "credential"},
		{name: "oauth access token", raw: "ref=main&access_token=x", wantErr: "credential"},
		{name: "job token", raw: "job_token=x", wantErr: "credential"},
		{name: "bare token", raw: "TOKEN=x", wantErr: "credential"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalizeQuery(tt.raw)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("CanonicalizeQuery(%q) = %q, want error", tt.raw, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("CanonicalizeQuery(%q) error = %q, want it to mention %q", tt.raw, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalizeQuery(%q) error = %v, want nil", tt.raw, err)
			}
			if got != tt.want {
				t.Errorf("CanonicalizeQuery(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// TestCanonicalizePathIdempotent guards the canonicalize-once contract: feeding a
// canonical path back in must not change it, so what we matched is what we send.
func TestCanonicalizePathIdempotent(t *testing.T) {
	for _, raw := range []string{
		"/api/v4/user",
		"/api/v4/projects/eng%2fplatform/repository/tree",
		"/api/v4/projects/42/repository/branches/feature%2Flogin",
	} {
		once, err := CanonicalizePath(raw)
		if err != nil {
			t.Fatalf("CanonicalizePath(%q) error = %v", raw, err)
		}
		twice, err := CanonicalizePath(once)
		if err != nil {
			t.Fatalf("CanonicalizePath(%q) error = %v", once, err)
		}
		if once != twice {
			t.Errorf("CanonicalizePath not idempotent: %q -> %q -> %q", raw, once, twice)
		}
	}
}
