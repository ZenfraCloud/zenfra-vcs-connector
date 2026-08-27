// ABOUTME: Canonicalize-once validation of tunneled request paths and query strings.
// ABOUTME: Rejects every ambiguous encoding pre-match so the allowlist matches what we send.
package policy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Size caps on one tunneled request line. Anything larger is a probe, not a call
// Zenfra makes.
const (
	maxPathBytes  = 2048
	maxQueryBytes = 4096
)

// CanonicalizePath validates an endpoint-relative request path and returns the
// exact bytes to send upstream. Structure is never rewritten — the only change is
// uppercasing percent-escape hex — so the string the allowlist matched is the
// string that reaches the VCS. Percent escapes are decoded for validation only:
// decoding them for real would turn an encoded project path (eng%2Fplatform) into
// extra path segments and change what the request means.
func CanonicalizePath(raw string) (string, error) {
	switch {
	case raw == "":
		return "", errors.New("path is empty")
	case len(raw) > maxPathBytes:
		return "", fmt.Errorf("path is too long (%d bytes, max %d)", len(raw), maxPathBytes)
	case !strings.HasPrefix(raw, "/"):
		return "", errors.New("path must start with /")
	}
	if err := rejectUnsafeRunes(raw, "path"); err != nil {
		return "", err
	}
	if strings.Contains(raw, "://") {
		return "", errors.New("path must not contain an absolute URL")
	}
	// %25 is an encoded percent: accepting it means the upstream would decode a
	// second layer we never inspected.
	if strings.Contains(raw, "%25") {
		return "", errors.New("path must not be double-encoded (%25)")
	}
	if strings.Contains(raw, "?") {
		return "", errors.New("path must not contain a query string")
	}
	if strings.Contains(raw, "#") {
		return "", errors.New("path must not contain a fragment")
	}
	if strings.Contains(raw, "@") {
		return "", errors.New("path must not contain @ (userinfo)")
	}

	segments := strings.Split(raw, "/")
	for i, segment := range segments[1:] {
		if segment == "" {
			return "", fmt.Errorf("path must not contain an empty segment (position %d)", i+1)
		}
		if err := validateSegment(segment); err != nil {
			return "", err
		}
		segments[i+1] = upperEscapes(segment)
	}
	return strings.Join(segments, "/"), nil
}

// validateSegment checks one encoded segment through its decoded form. A segment
// may legitimately decode to several parts (eng%2Fplatform), so each decoded part
// is checked as a path component in its own right.
func validateSegment(segment string) error {
	decoded, err := url.PathUnescape(segment)
	if err != nil {
		return fmt.Errorf("path has invalid percent-encoding in %q", segment)
	}
	if err := rejectUnsafeRunes(decoded, "decoded path"); err != nil {
		return err
	}
	if strings.ContainsAny(decoded, "?#@") {
		return fmt.Errorf("path must not encode a query, fragment or @ (segment %q)", segment)
	}
	for _, part := range strings.Split(decoded, "/") {
		switch part {
		case "":
			return fmt.Errorf("path must not contain an empty segment (segment %q)", segment)
		case ".", "..":
			return fmt.Errorf("path must not contain a dot segment (segment %q)", segment)
		}
	}
	return nil
}

// CanonicalizeQuery validates a raw query string. Unlike the path it is not
// decoded or normalized: it never selects a rule, and a value may legitimately
// carry an encoded percent (search=50%25).
func CanonicalizeQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if len(raw) > maxQueryBytes {
		return "", fmt.Errorf("query is too long (%d bytes, max %d)", len(raw), maxQueryBytes)
	}
	if strings.HasPrefix(raw, "?") {
		return "", errors.New("query must not start with ?")
	}
	if err := rejectUnsafeRunes(raw, "query"); err != nil {
		return "", err
	}
	if strings.Contains(raw, "#") {
		return "", errors.New("query must not contain a fragment")
	}
	if _, err := url.ParseQuery(raw); err != nil {
		return "", fmt.Errorf("query has invalid percent-encoding or syntax: %w", err)
	}
	return raw, nil
}

// rejectUnsafeRunes denies control characters (header/request smuggling) and
// backslashes (path separators on the upstream's filesystem or a Windows client).
func rejectUnsafeRunes(s, what string) error {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c < 0x20 || c == 0x7f:
			return fmt.Errorf("%s must not contain a control character (0x%02x at %d)", what, c, i)
		case c == '\\':
			return fmt.Errorf("%s must not contain a backslash (at %d)", what, i)
		}
	}
	return nil
}

// upperEscapes uppercases the hex digits of percent escapes so equivalent paths
// compare and hash identically. Every % is known to be followed by two hex digits
// because the segment already survived url.PathUnescape.
func upperEscapes(segment string) string {
	if !strings.Contains(segment, "%") {
		return segment
	}
	out := []byte(segment)
	for i := 0; i+2 < len(out); i++ {
		if out[i] == '%' {
			out[i+1] = upperHex(out[i+1])
			out[i+2] = upperHex(out[i+2])
		}
	}
	return string(out)
}

func upperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}
