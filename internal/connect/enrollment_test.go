// ABOUTME: Tests for per-instance enrollment key persistence and its use at registration.
// ABOUTME: Covers first enrollment, restart with the stored key, and refusal without bootstrap fallback.
package connect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Registration credentials used across these tests. Both are fixtures.
const (
	testBootstrapToken = "vcsc_boot.strap"         //nolint:gosec // test fixture
	testBootstrapAuth  = "Bearer vcsc_boot.strap"  //nolint:gosec // test fixture
	testEnrollmentAuth = "Bearer vcsi_i1.secret-1" //nolint:gosec // test fixture
	testEnrollmentKey  = "vcsi_i1.secret-1"        //nolint:gosec // test fixture
)

// enrollPlane is a control plane that records every credential presented to
// register and hands out a per-instance enrollment key on the bootstrap path.
type enrollPlane struct {
	srv *httptest.Server

	mu sync.Mutex
	// presented records the Authorization value of every register call.
	presented []string
	// rejectEnrolled refuses registrations made with an enrollment key.
	rejectEnrolled bool
	issued         int
}

func newEnrollPlane(t *testing.T) *enrollPlane {
	t.Helper()
	p := &enrollPlane{}

	mux := http.NewServeMux()
	mux.HandleFunc(registerPath, func(w http.ResponseWriter, r *http.Request) {
		credential := r.Header.Get("Authorization")
		p.mu.Lock()
		p.presented = append(p.presented, credential)
		reject := p.rejectEnrolled && credential != testBootstrapAuth
		p.issued++
		key := "vcsi_i1.secret-" + string(rune('0'+p.issued%10))
		p.mu.Unlock()

		if reject {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "instance_revoked", "message": "this connector instance has been revoked",
			})
			return
		}

		body := map[string]any{
			"connector_id": "c1",
			"instance_id":  "i1",
			"token":        "jwt-1",
			"expires_at":   time.Now().Add(time.Hour),
			"endpoint":     "https://gitlab.internal",
			"vendor":       "gitlab",
		}
		// Only bootstrap registration issues a key, mirroring the API.
		if credential == testBootstrapAuth {
			body["enrollment_key"] = key
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(body)
	})

	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *enrollPlane) credentials() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.presented...)
}

// newEnrollTokenSource builds a token source against the plane, storing its key
// at path. A fresh one models a connector restart on the same host.
func newEnrollTokenSource(p *enrollPlane, path string) *tokenSource {
	return &tokenSource{
		client:         NewClient(p.srv.URL, nil),
		bootstrapToken: testBootstrapToken,
		enrollment:     enrollmentStore{path: path},
		instanceKey:    "connector-0",
		version:        "test",
		skew:           DefaultRefreshSkew,
		now:            time.Now,
		logger:         testLogger(),
	}
}

func TestEnrollmentStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment-key")
	store := enrollmentStore{path: path}

	if got := store.load(); got != "" {
		t.Errorf("load() with no file = %q, want empty", got)
	}
	if err := store.save("vcsi_abc.first"); err != nil {
		t.Fatalf("save() error = %v", err)
	}
	if got := store.load(); got != "vcsi_abc.first" {
		t.Errorf("load() = %q, want the saved key", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %v, want 0600 — it is a credential", perm)
	}

	// Re-enrolling replaces the key rather than appending to it.
	if err := store.save("vcsi_abc.second"); err != nil {
		t.Fatalf("save() error = %v", err)
	}
	if got := store.load(); got != "vcsi_abc.second" {
		t.Errorf("load() after re-save = %q, want the new key", got)
	}

	// No stray temp files survive.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d files, want only the key file", len(entries))
	}
}

func TestEnrollmentStoreDisabledIsANoOp(t *testing.T) {
	store := enrollmentStore{}
	if store.enabled() {
		t.Error("a store with no path must be disabled")
	}
	if err := store.save("vcsi_abc.key"); err != nil {
		t.Errorf("save() on a disabled store error = %v, want nil", err)
	}
	if got := store.load(); got != "" {
		t.Errorf("load() on a disabled store = %q, want empty", got)
	}

	// An empty key is nothing to persist, even with a path.
	path := filepath.Join(t.TempDir(), "enrollment-key")
	if err := (enrollmentStore{path: path}).save(""); err != nil {
		t.Errorf("save(\"\") error = %v, want nil", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("saving an empty key must not create a file")
	}
}

func TestTokenSourceEnrollsThenRegistersWithTheStoredKey(t *testing.T) {
	plane := newEnrollPlane(t)
	path := filepath.Join(t.TempDir(), "enrollment-key")

	if _, err := newEnrollTokenSource(plane, path).get(context.Background()); err != nil {
		t.Fatalf("first get() error = %v", err)
	}

	stored, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("the first registration must persist the enrollment key: %v", err)
	}
	if string(stored) != testEnrollmentKey {
		t.Errorf("stored key = %q, want the one the control plane issued", stored)
	}

	// A restart registers with the stored key, never the bootstrap token again.
	if _, err := newEnrollTokenSource(plane, path).get(context.Background()); err != nil {
		t.Fatalf("second get() error = %v", err)
	}

	got := plane.credentials()
	want := []string{testBootstrapAuth, testEnrollmentAuth}
	if len(got) != len(want) {
		t.Fatalf("registrations = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("registration %d presented %q, want %q", i, got[i], want[i])
		}
	}
}

// TestTokenSourceNeverFallsBackToBootstrapAfterRevocation is the property
// per-instance keys exist for: once revoked, holding the fleet-wide bootstrap
// token must not get this instance back on the tunnel.
func TestTokenSourceNeverFallsBackToBootstrapAfterRevocation(t *testing.T) {
	plane := newEnrollPlane(t)
	path := filepath.Join(t.TempDir(), "enrollment-key")

	if _, err := newEnrollTokenSource(plane, path).get(context.Background()); err != nil {
		t.Fatalf("first get() error = %v", err)
	}

	plane.mu.Lock()
	plane.rejectEnrolled = true
	plane.mu.Unlock()

	_, err := newEnrollTokenSource(plane, path).get(context.Background())
	if err == nil {
		t.Fatal("get() with a revoked enrollment key must fail")
	}
	if IsRetryable(err) {
		t.Errorf("a revoked instance must stop, not retry: %v", err)
	}

	for i, credential := range plane.credentials() {
		if i > 0 && credential == testBootstrapAuth {
			t.Error("the connector must not retry registration with the bootstrap token")
		}
	}
}

func TestTokenSourceWithoutAKeyFileKeepsUsingTheBootstrapToken(t *testing.T) {
	plane := newEnrollPlane(t)

	source := newEnrollTokenSource(plane, "")
	if _, err := source.get(context.Background()); err != nil {
		t.Fatalf("get() error = %v", err)
	}
	source.cur = nil
	if _, err := source.get(context.Background()); err != nil {
		t.Fatalf("second get() error = %v", err)
	}

	for _, credential := range plane.credentials() {
		if credential != testBootstrapAuth {
			t.Errorf("presented %q, want the bootstrap token when no key file is configured", credential)
		}
	}
}

func TestTokenSourceSurvivesAnUnwritableKeyFile(t *testing.T) {
	plane := newEnrollPlane(t)
	// A directory that does not exist makes the atomic write fail.
	path := filepath.Join(t.TempDir(), "missing", "enrollment-key")

	if _, err := newEnrollTokenSource(plane, path).get(context.Background()); err != nil {
		t.Fatalf("a token that works must not be discarded over a failed key write: %v", err)
	}
}
