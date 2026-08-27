// ABOUTME: Persistence for this instance's per-instance enrollment key.
// ABOUTME: With a key stored, the bootstrap token is used once and revocation cannot be undone with it.
package connect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// enrollmentStore reads and writes the per-instance enrollment key. A zero-value
// store (empty path) is disabled: the connector then registers with the
// bootstrap token every time, which is the Phase 1 behaviour.
type enrollmentStore struct{ path string }

// enabled reports whether a key file is configured.
func (s enrollmentStore) enabled() bool { return s.path != "" }

// load returns the stored key, or "" when none is configured or readable. A
// missing or unreadable file is not an error: the connector falls back to the
// bootstrap token and re-enrolls, which is exactly what a fresh host needs.
func (s enrollmentStore) load() string {
	if !s.enabled() {
		return ""
	}
	raw, err := os.ReadFile(s.path) // #nosec G304 -- operator-supplied path, same as the credential file
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// save writes the key 0600, replacing any previous one atomically so a crash
// mid-write cannot leave a half-written key that authenticates as nothing.
func (s enrollmentStore) save(key string) error {
	if !s.enabled() || key == "" {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".enrollment-*")
	if err != nil {
		return fmt.Errorf("create enrollment key temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod enrollment key: %w", err)
	}
	if _, err := tmp.WriteString(key); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write enrollment key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close enrollment key: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("install enrollment key: %w", err)
	}
	return nil
}
