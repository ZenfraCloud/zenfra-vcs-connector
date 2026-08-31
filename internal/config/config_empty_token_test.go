// ABOUTME: Tests the empty-vs-unset bootstrap token distinction in config errors.
// ABOUTME: An empty value almost always means $(cat missing-file) evaluated to nothing.

package config

import (
	"strings"
	"testing"
)

// A set-but-empty token is a different mistake than an unset one: the shell
// evaluated something like "$(cat /etc/zenfra/bootstrap-token)" against a file
// that did not exist and handed us an empty string. Seen in a real install; the
// generic "is required" message sent the operator looking in the wrong place.
func TestEmptyBootstrapTokenNamesTheLikelyCause(t *testing.T) {
	env := map[string]string{
		EnvBootstrapToken:  "   ",
		EnvGatewayURL:      "https://api.example.com",
		EnvEndpoint:        "https://gitlab.example.com",
		EnvVendor:          "gitlab",
		EnvAllowedProjects: "1",
	}
	_, err := Load(nil, func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("empty bootstrap token must fail validation")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error must say the token was empty, not merely missing: %v", err)
	}
}
