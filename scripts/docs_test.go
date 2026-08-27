// ABOUTME: Checks that the opt-in modes ship with a page stating what they cost.
// ABOUTME: A mode that gives up a security property is not done until the trade-off is written down.
package scripts

import (
	"os"
	"strings"
	"testing"
)

// optionalModesDoc is the page the connector's startup warnings point operators at.
const optionalModesDoc = "../docs/optional-modes.md"

func TestOptionalModesDocNamesTheTradeOffs(t *testing.T) {
	raw, err := os.ReadFile(optionalModesDoc)
	if err != nil {
		t.Fatalf("reading %s: %v", optionalModesDoc, err)
	}
	page := string(raw)

	for _, want := range []string{
		// The control_plane credential mode and the exposure it buys.
		"control_plane",
		"--credential-mode",
		"off by default",
		"token leaves your network",
		"TLS-intercepting proxy",
		"GitLab only",
		// The blocklist policy mode and the guarantee it drops.
		"--policy-mode blocklist",
		"best-effort",
		"--all-projects",
		"blocklist.unlisted",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("%s does not mention %q", optionalModesDoc, want)
		}
	}
}
