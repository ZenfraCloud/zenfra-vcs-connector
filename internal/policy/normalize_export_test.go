// ABOUTME: Tests the exported normalization the connector advertises its allowlist with.
// ABOUTME: Server-side matching only works if both sides normalize to identical bytes.

package policy

import (
	"reflect"
	"testing"
)

// The advertised list must round-trip through exactly the same rule the engine
// applies to incoming requests, or the server filters on different bytes than
// the connector enforces.
func TestNormalizeProjectsMatchesEngineRule(t *testing.T) {
	in := []string{" 179 ", "/Group/Proj/", "TEAM/Repo", ""}
	got := NormalizeProjects(in)
	want := []string{"179", "group/proj", "team/repo"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeProjects(%v) = %v, want %v", in, got, want)
	}
}

// Empty input stays empty, not nil-vs-empty surprises in the JSON payload.
func TestNormalizeProjectsEmpty(t *testing.T) {
	if got := NormalizeProjects(nil); len(got) != 0 {
		t.Fatalf("NormalizeProjects(nil) = %v, want empty", got)
	}
}
