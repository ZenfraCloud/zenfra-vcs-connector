// ABOUTME: Runnable checks for the connector's distribution artifacts.
// ABOUTME: Reproducible-build verification, goreleaser config validity, Helm chart wiring.
package scripts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// chartDir is the Helm chart, relative to this package.
const chartDir = "../deploy/helm/zenfra-vcs-connector"

// chartValues are the values a real install must supply; the chart refuses to
// render without them, which TestHelmChartRequiresConnectorValues asserts.
var chartValues = []string{
	"--set", "connector.gatewayUrl=https://api.zenfra.cloud",
	"--set", "connector.endpoint=https://gitlab.internal",
	"--set", "connector.allowedProjects={acme/infra}",
	"--set", "secret.name=zenfra-vcs-connector",
}

// runTool executes a packaging tool and returns its combined output.
func runTool(t *testing.T, timeout time.Duration, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	//nolint:gosec // test-only: every name and argument is a literal in this file
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// requireTool skips when a packaging tool is absent. The tools are pinned in the
// release workflow, so CI always has them; a laptop may not.
func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not installed", name)
	}
}

// TestReproducibleBuild is the check a customer runs to confirm a published
// binary matches this source: two builds from different paths, same bytes.
func TestReproducibleBuild(t *testing.T) {
	out, err := runTool(t, 10*time.Minute, "./verify-reproducible-build.sh", "--version", "v0.0.0-test")
	if err != nil {
		t.Fatalf("verify-reproducible-build.sh failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "reproducible: ") {
		t.Fatalf("expected a digest on success, got:\n%s", out)
	}
}

// TestReproducibleBuildRejectsUnknownFlags guards the argument parsing: a typo
// must fail loudly rather than silently verify the default target.
func TestReproducibleBuildRejectsUnknownFlags(t *testing.T) {
	out, err := runTool(t, time.Minute, "./verify-reproducible-build.sh", "--goarhc", "arm64")
	if err == nil {
		t.Fatalf("expected failure on an unknown flag, got:\n%s", out)
	}
	if !strings.Contains(out, "unknown argument") {
		t.Fatalf("expected an unknown-argument message, got:\n%s", out)
	}
}

// TestGoreleaserConfigIsValid runs goreleaser's own validation over the release
// config, which catches renamed and deprecated fields on a version bump.
func TestGoreleaserConfigIsValid(t *testing.T) {
	requireTool(t, "goreleaser")
	out, err := runTool(t, 2*time.Minute, "goreleaser", "check", "--config", "../.goreleaser.yaml")
	if err != nil {
		t.Fatalf("goreleaser check failed: %v\n%s", err, out)
	}
}

// TestHelmChartLints is the checkbox `helm lint` passes, with the values a real
// install supplies.
func TestHelmChartLints(t *testing.T) {
	requireTool(t, "helm")
	args := append([]string{"lint", chartDir}, chartValues...)
	out, err := runTool(t, time.Minute, "helm", args...)
	if err != nil {
		t.Fatalf("helm lint failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "0 chart(s) failed") {
		t.Fatalf("expected a clean lint, got:\n%s", out)
	}
}

// TestHelmChartRequiresConnectorValues asserts the chart refuses to render
// without the settings that have no safe default — a connector pointed at the
// wrong endpoint or missing its credential Secret must fail at install time,
// not crash-loop in the customer's cluster.
func TestHelmChartRequiresConnectorValues(t *testing.T) {
	requireTool(t, "helm")
	out, err := runTool(t, time.Minute, "helm", "template", "release", chartDir)
	if err == nil {
		t.Fatalf("expected render to fail without required values, got:\n%s", out)
	}
	if !strings.Contains(out, "connector.gatewayUrl is required") {
		t.Fatalf("expected the missing-value error to name the value, got:\n%s", out)
	}
}

// TestHelmChartRendersConnectorWiring covers the four things the chart exists
// to get right: the credential arrives as a mounted file (never an env var),
// the proxy variables reach the process, the CA bundles are wired to their
// flags, and the pod is resource-bounded.
func TestHelmChartRendersConnectorWiring(t *testing.T) {
	requireTool(t, "helm")
	args := append([]string{"template", "release", chartDir}, chartValues...)
	args = append(args,
		"--set", "proxy.httpsProxy=http://proxy.internal:3128",
		"--set", "proxy.noProxy=.internal",
		"--set", "caBundle.configMapName=corp-ca",
		"--set", "caBundle.gatewayKey=gateway.pem",
		"--set", "caBundle.upstreamKey=vcs.pem",
		"--set", "metrics.enabled=true",
	)
	out, err := runTool(t, time.Minute, "helm", args...)
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}

	for _, want := range []string{
		// The credential is a file read per request, mounted read-only.
		"name: ZENFRA_VCS_CONNECTOR_SECRET_FILE",
		"value: \"/etc/zenfra-vcs-connector/secrets/credential\"",
		"secretName: \"zenfra-vcs-connector\"",
		// The bootstrap token comes from the same Secret, never from values.
		"secretKeyRef",
		// Egress through a corporate proxy.
		"name: HTTPS_PROXY",
		"value: \"http://proxy.internal:3128\"",
		"name: NO_PROXY",
		// Internal CAs for both TLS legs.
		"value: \"/etc/zenfra-vcs-connector/ca/gateway.pem\"",
		"value: \"/etc/zenfra-vcs-connector/ca/vcs.pem\"",
		"name: \"corp-ca\"",
		// Metrics listener and resource bounds.
		"value: \"0.0.0.0:9090\"",
		"memory: 256Mi",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered chart missing %q", want)
		}
	}

	// Secret material must never be templated into a manifest.
	if strings.Contains(out, "kind: Secret") {
		t.Error("chart must not template a Secret; the credential is pre-created by the operator")
	}
}

// TestVerificationScriptMatchesReleaseBuild is the check that keeps the promise
// honest: the script's build flags must be the ones goreleaser uses, or a
// customer verifying a published binary gets a mismatch and no way to tell
// whether the release or the script is wrong.
func TestVerificationScriptMatchesReleaseBuild(t *testing.T) {
	requireTool(t, "goreleaser")

	binary := filepath.Join(t.TempDir(), "connector")
	//nolint:gosec // test-only: fixed command, only the output path varies
	cmd := exec.Command("goreleaser", "build",
		"--config", ".goreleaser.yaml", "--clean", "--single-target",
		"--skip=validate", "-o", binary)
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(),
		"GOOS=linux", "GOARCH=amd64", "GORELEASER_CURRENT_TAG=v9.9.9")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("goreleaser build failed: %v\n%s", err, out)
	}
	// goreleaser insists on writing its dist/ next to the config.
	t.Cleanup(func() { _ = os.RemoveAll("../dist") })

	sum := sha256.New()
	f, err := os.Open(binary) //nolint:gosec // path built from t.TempDir
	if err != nil {
		t.Fatalf("open release binary: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(sum, f); err != nil {
		t.Fatalf("hash release binary: %v", err)
	}
	digest := hex.EncodeToString(sum.Sum(nil))

	// The tag form (with "v") must verify against the stamped form (without).
	out, err := runTool(t, 10*time.Minute, "./verify-reproducible-build.sh",
		"--version", "v9.9.9", "--expect", digest)
	if err != nil {
		t.Fatalf("script build does not match the release build: %v\n%s", err, out)
	}
}

// TestVerificationScriptDetectsDigestMismatch proves --expect is a real gate:
// without this, a script that silently ignored the expected digest would report
// success against any published SHA256SUMS.
func TestVerificationScriptDetectsDigestMismatch(t *testing.T) {
	out, err := runTool(t, 10*time.Minute, "./verify-reproducible-build.sh",
		"--version", "v9.9.9", "--expect", strings.Repeat("0", 64))
	if err == nil {
		t.Fatalf("expected a mismatch failure, got:\n%s", out)
	}
	if !strings.Contains(out, "DIGEST MISMATCH") {
		t.Fatalf("expected a digest-mismatch message, got:\n%s", out)
	}
}
