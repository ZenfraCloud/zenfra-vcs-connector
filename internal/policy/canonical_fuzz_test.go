// ABOUTME: Fuzz targets asserting the canonicalizer's security invariants hold for any input.
// ABOUTME: Table tests cover known attacks; these prove no unknown input slips past them.
package policy

import (
	"net/url"
	"strings"
	"testing"
)

// canonicalPathSeeds are the shapes worth starting the corpus from: every
// rejection class from TestCanonicalizePathRejects plus the accepted forms, so
// the fuzzer mutates around the boundary instead of random noise.
var canonicalPathSeeds = []string{
	"/api/v4/user",
	"/api/v4/projects/eng%2Fplatform/repository/archive.tar.gz",
	"/api/v4/projects/ENG%2fplatform",
	"",
	"api/v4/user",
	"//gitlab.evil/api/v4/user",
	"https://gitlab.evil/api/v4/user",
	"/https://gitlab.evil/api/v4/user",
	"/api/v4/./user",
	"/api/v4/../admin/users",
	"/api/v4/%2e%2e/admin/users",
	"/api/v4/%2E%2E/admin/users",
	"/api/v4/projects/eng%2F..%2Fother",
	"/api/v4/%252e%252e/admin/users",
	"/api/v4\\admin\\users",
	"/api/v4/%5cadmin",
	"/api/v4//user",
	"/api/v4/user?private_token=x",
	"/api/v4/user#frag",
	"/api/v4/user@gitlab.evil",
	"/api/v4/us\x00er",
	"/api/v4/user%0Ax",
	"/api/v4/user%",
	"/api/v4/user%zz",
}

// FuzzCanonicalizePath asserts that anything CanonicalizePath accepts is safe to
// put on the wire: it is what the allowlist matched, it re-canonicalizes to
// itself, and it carries none of the ambiguity the matcher would have to guess at.
func FuzzCanonicalizePath(f *testing.F) {
	for _, seed := range canonicalPathSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		got, err := CanonicalizePath(raw)
		if err != nil {
			if got != "" {
				t.Fatalf("CanonicalizePath(%q) = %q with error %v, want empty path on rejection", raw, got, err)
			}
			return
		}

		assertAcceptedPathShape(t, raw, got)
		assertSegmentsDecodeSafely(t, raw, got)

		again, err := CanonicalizePath(got)
		if err != nil {
			t.Fatalf("CanonicalizePath(%q) = %q, which was then rejected: %v", raw, got, err)
		}
		if again != got {
			t.Fatalf("CanonicalizePath is not idempotent: %q -> %q -> %q", raw, got, again)
		}
	})
}

// assertAcceptedPathShape checks the whole-string invariants of an accepted path.
func assertAcceptedPathShape(t *testing.T, raw, got string) {
	t.Helper()
	if !strings.HasPrefix(got, "/") {
		t.Fatalf("CanonicalizePath(%q) = %q, accepted path must start with /", raw, got)
	}
	// Structure is never rewritten — only escape hex case changes — so the path
	// the allowlist matched is byte-for-byte what reaches the VCS.
	if len(got) != len(raw) || !strings.EqualFold(got, raw) {
		t.Fatalf("CanonicalizePath(%q) = %q, only escape hex case may differ", raw, got)
	}
	for _, forbidden := range []string{"://", "%25", "?", "#", "@", "\\"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("CanonicalizePath(%q) = %q, accepted path must not contain %q", raw, got, forbidden)
		}
	}
	for i := 0; i < len(got); i++ {
		if c := got[i]; c < 0x20 || c == 0x7f {
			t.Fatalf("CanonicalizePath(%q) = %q, accepted path must not contain control byte 0x%02x", raw, got, c)
		}
	}
}

// assertSegmentsDecodeSafely checks every segment of an accepted path through its
// decoded form: a segment may legitimately decode to several parts
// (eng%2Fplatform), and none of them may be empty or a dot segment.
func assertSegmentsDecodeSafely(t *testing.T, raw, got string) {
	t.Helper()
	for _, segment := range strings.Split(got, "/")[1:] {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			t.Fatalf("CanonicalizePath(%q) = %q, accepted segment %q does not decode: %v", raw, got, segment, err)
		}
		// The raw form is checked for ?#@ elsewhere; the decoded form must be too,
		// or %3F/%23/%40 would smuggle one past the allowlist into the upstream URL.
		if i := strings.IndexAny(decoded, "?#@"); i >= 0 {
			t.Fatalf("CanonicalizePath(%q) = %q, segment %q decodes to %q containing %q",
				raw, got, segment, decoded, decoded[i])
		}
		for _, part := range strings.Split(decoded, "/") {
			switch part {
			case "":
				t.Fatalf("CanonicalizePath(%q) = %q, segment %q decodes to an empty part", raw, got, segment)
			case ".", "..":
				t.Fatalf("CanonicalizePath(%q) = %q, segment %q decodes to a dot segment", raw, got, segment)
			}
		}
	}
}

// FuzzCanonicalizeQuery asserts an accepted query is returned verbatim and stays
// free of the bytes that would let it smuggle a header or a fragment upstream.
func FuzzCanonicalizeQuery(f *testing.F) {
	for _, seed := range []string{
		"", "per_page=100", "search=50%25", "ref=main&recursive=true",
		"?per_page=100", "a=1#frag", "a=%zz", "bad\x00=1", "a=b\\c",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		got, err := CanonicalizeQuery(raw)
		if err != nil {
			if got != "" {
				t.Fatalf("CanonicalizeQuery(%q) = %q with error %v, want empty query on rejection", raw, got, err)
			}
			return
		}
		if got != raw {
			t.Fatalf("CanonicalizeQuery(%q) = %q, accepted query must be returned verbatim", raw, got)
		}
		if strings.Contains(got, "#") {
			t.Fatalf("CanonicalizeQuery(%q) = %q, accepted query must not contain a fragment", raw, got)
		}
		if strings.Contains(got, "\\") {
			t.Fatalf("CanonicalizeQuery(%q) = %q, accepted query must not contain a backslash", raw, got)
		}
		for i := 0; i < len(got); i++ {
			if c := got[i]; c < 0x20 || c == 0x7f {
				t.Fatalf("CanonicalizeQuery(%q) = %q, accepted query must not contain control byte 0x%02x", raw, got, c)
			}
		}
		if _, err := url.ParseQuery(got); err != nil {
			t.Fatalf("CanonicalizeQuery(%q) = %q, which does not parse: %v", raw, got, err)
		}
	})
}
