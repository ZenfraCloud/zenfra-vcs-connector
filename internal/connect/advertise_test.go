// ABOUTME: Tests that registration advertises the connector's project allowlist.
// ABOUTME: The server filters discovery on this copy; enforcement stays local.

package connect

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func captureRegisterBody(t *testing.T, configure func(*Client)) map[string]any {
	t.Helper()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("register body is not JSON: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connector_id":"c","instance_id":"i","token":"tok"}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, nil)
	if configure != nil {
		configure(client)
	}
	if _, err := client.Register(t.Context(), "vcsc_x", "inst-1", "0.2.0"); err != nil {
		t.Fatalf("register: %v", err)
	}
	return body
}

// A configured allowlist rides along on registration, verbatim as handed over —
// normalization is the caller's job so this layer stays dumb.
func TestRegisterAdvertisesAllowedProjects(t *testing.T) {
	body := captureRegisterBody(t, func(c *Client) {
		c.SetAdvertisedScope([]string{"179", "group/proj"}, false)
	})

	got, ok := body["allowed_projects"].([]any)
	if !ok || len(got) != 2 || got[0] != "179" || got[1] != "group/proj" {
		t.Fatalf("allowed_projects = %v, want [179 group/proj]", body["allowed_projects"])
	}
	if all, ok := body["all_projects"].(bool); !ok || all {
		t.Fatalf("all_projects = %v, want false", body["all_projects"])
	}
}

// --all-projects advertises the flag with an empty list.
func TestRegisterAdvertisesAllProjects(t *testing.T) {
	body := captureRegisterBody(t, func(c *Client) {
		c.SetAdvertisedScope(nil, true)
	})

	if all, ok := body["all_projects"].(bool); !ok || !all {
		t.Fatalf("all_projects = %v, want true", body["all_projects"])
	}
}

// A client never told its scope sends neither field, so an old-style connector
// registration is byte-compatible and the server treats the scope as unknown.
func TestRegisterWithoutScopeOmitsTheFields(t *testing.T) {
	body := captureRegisterBody(t, nil)

	if _, present := body["allowed_projects"]; present {
		t.Fatalf("allowed_projects present without scope: %v", body["allowed_projects"])
	}
	if _, present := body["all_projects"]; present {
		t.Fatalf("all_projects present without scope: %v", body["all_projects"])
	}
}
