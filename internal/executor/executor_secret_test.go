// ABOUTME: Tests for readSecret's failure messages, which are install-time UX.
// ABOUTME: A missing bind-mount source becomes a directory; the error must say so.

package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Docker creates a missing bind-mount source as a directory, silently. The
// resulting error is the first thing a customer sees, so it has to name that
// cause — a bare EISDIR sent a real install down a support round-trip.
func TestReadSecretNamesTheDockerDirectoryTrap(t *testing.T) {
	dir := t.TempDir()

	_, err := readSecret(dir)
	if err == nil {
		t.Fatal("reading a directory as a secret must fail")
	}
	if !strings.Contains(err.Error(), "is a directory") ||
		!strings.Contains(err.Error(), "did not exist") {
		t.Fatalf("error must explain the missing-mount-source cause, got: %v", err)
	}
}

// A regular missing file keeps the plain not-found error.
func TestReadSecretMissingFileStaysPlain(t *testing.T) {
	_, err := readSecret(filepath.Join(t.TempDir(), "absent"))
	if err == nil || strings.Contains(err.Error(), "did not exist before") {
		t.Fatalf("missing file must not claim the directory trap, got: %v", err)
	}
	if !os.IsNotExist(errUnwrapAll(err)) {
		t.Fatalf("want not-exist error, got: %v", err)
	}
}

func errUnwrapAll(err error) error {
	for {
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok || u.Unwrap() == nil {
			return err
		}
		err = u.Unwrap()
	}
}
