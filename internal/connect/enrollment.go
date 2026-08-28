// ABOUTME: Persistence for this instance's per-instance enrollment key.
// ABOUTME: With a key stored, the bootstrap token is used once and revocation cannot be undone with it.
package connect

import (
	"errors"
	"fmt"
	"io/fs"
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

// load returns the stored key, or "" when none is configured or the file does
// not exist yet — a fresh host falls back to the bootstrap token and enrolls.
// Any other read error is returned: a permissions change or an unmounted volume
// is indistinguishable from a fresh host otherwise, and the fallback would
// re-enrol a revoked instance on the fleet-wide credential.
func (s enrollmentStore) load() (string, error) {
	if !s.enabled() {
		return "", nil
	}
	raw, err := os.ReadFile(s.path) // #nosec G304 -- operator-supplied path, same as the credential file
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading enrollment key: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
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
