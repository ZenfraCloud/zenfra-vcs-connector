// ABOUTME: Connector configuration loaded from flags with environment fallbacks.
// ABOUTME: Validation failures are terminal (ErrInvalidConfig) — the caller exits, never retries.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
)

// Vendor is the VCS flavour this connector fronts.
type Vendor string

const (
	// VendorGitLab is a self-managed GitLab instance.
	VendorGitLab Vendor = "gitlab"
	// VendorGitHub is a self-managed GitHub Enterprise Server instance. GitHub.com
	// needs no connector, so the REST surface here is the /api/v3 one.
	VendorGitHub Vendor = "github"
	// VendorBitbucket is a Bitbucket Data Center / Server instance. Bitbucket
	// Cloud is a different API and needs no connector, so the REST surface here
	// is the /rest/api/1.0 one.
	VendorBitbucket Vendor = "bitbucket"
	// VendorAzureDevOps is an Azure DevOps Server (formerly TFS) collection. The
	// endpoint includes the collection — /_apis lives under it — so a tunneled
	// path starts at the project or at _apis itself.
	VendorAzureDevOps Vendor = "azure_devops"
)

// supportedVendors is the set --vendor accepts, in the order the error lists them.
var supportedVendors = []Vendor{VendorGitLab, VendorGitHub, VendorBitbucket, VendorAzureDevOps}

// supported reports whether v has a compiled allowlist.
func (v Vendor) supported() bool {
	for _, candidate := range supportedVendors {
		if v == candidate {
			return true
		}
	}
	return false
}

// CredentialMode names who supplies the upstream VCS credential.
type CredentialMode string

const (
	// CredentialModeAgentLocal is the default and recommended mode: the credential
	// lives in this network, is read from --secret-file after policy approval, and
	// Zenfra never holds it. An inbound credential is refused.
	CredentialModeAgentLocal CredentialMode = "agent_local"
	// CredentialModeControlPlane is the opt-in mode where Zenfra stores the
	// credential and sends it over the tunnel, and this connector forwards it
	// upstream. It trades the token-stays-home property away — see
	// docs/optional-modes.md.
	CredentialModeControlPlane CredentialMode = "control_plane"
)

// PolicyMode selects how the connector decides what may reach the upstream.
type PolicyMode string

const (
	// PolicyModeAllowlist is the default: only compiled-in operations pass.
	PolicyModeAllowlist PolicyMode = "allowlist"
	// PolicyModeBlocklist is the opt-in advanced mode: anything the compiled
	// allowlist does not cover is allowed unless it hits the deny table.
	PolicyModeBlocklist PolicyMode = "blocklist"
)

// DefaultInteractiveConnections is the interactive stream count per instance; one
// bulk stream is always opened alongside them.
const DefaultInteractiveConnections = 3

// maxInteractiveConnections bounds --interactive-connections. The gateway caps
// the live streams one connector may hold, so a larger fleet needs more
// instances, not more lanes per instance.
const maxInteractiveConnections = 16

// Environment variables, each mirroring the flag of the same name.
const (
	EnvGatewayURL             = "ZENFRA_VCS_CONNECTOR_GATEWAY_URL"
	EnvBootstrapToken         = "ZENFRA_VCS_CONNECTOR_BOOTSTRAP_TOKEN" //nolint:gosec // env var name
	EnvEndpoint               = "ZENFRA_VCS_CONNECTOR_ENDPOINT"
	EnvCodeloadEndpoint       = "ZENFRA_VCS_CONNECTOR_CODELOAD_ENDPOINT"
	EnvVendor                 = "ZENFRA_VCS_CONNECTOR_VENDOR"
	EnvSecretFile             = "ZENFRA_VCS_CONNECTOR_SECRET_FILE" //nolint:gosec // env var name
	EnvAllowedProjects        = "ZENFRA_VCS_CONNECTOR_ALLOWED_PROJECTS"
	EnvAllProjects            = "ZENFRA_VCS_CONNECTOR_ALL_PROJECTS"
	EnvCredentialMode         = "ZENFRA_VCS_CONNECTOR_CREDENTIAL_MODE" //nolint:gosec // env var name
	EnvPolicyMode             = "ZENFRA_VCS_CONNECTOR_POLICY_MODE"
	EnvInstanceKey            = "ZENFRA_VCS_CONNECTOR_INSTANCE_KEY"
	EnvEnrollmentKeyFile      = "ZENFRA_VCS_CONNECTOR_ENROLLMENT_KEY_FILE" //nolint:gosec // env var name
	EnvCABundle               = "ZENFRA_VCS_CONNECTOR_CA_BUNDLE"
	EnvUpstreamCABundle       = "ZENFRA_VCS_CONNECTOR_UPSTREAM_CA_BUNDLE"
	EnvInteractiveConnections = "ZENFRA_VCS_CONNECTOR_INTERACTIVE_CONNECTIONS"
	EnvLogLevel               = "ZENFRA_VCS_CONNECTOR_LOG_LEVEL"
	EnvMetricsAddr            = "ZENFRA_VCS_CONNECTOR_METRICS_ADDR"
	EnvWebhookAddr            = "ZENFRA_VCS_CONNECTOR_WEBHOOK_ADDR"
	EnvWebhookSecretFile      = "ZENFRA_VCS_CONNECTOR_WEBHOOK_SECRET_FILE" //nolint:gosec // env var name
)

// ErrInvalidConfig marks a terminal configuration problem. A connector that gets
// one must exit rather than retry: no amount of waiting fixes a bad flag.
var ErrInvalidConfig = errors.New("invalid configuration")

// ErrHelpRequested reports that -h/--help was asked for and the usage has already
// been printed. Not a failure: the caller exits 0.
var ErrHelpRequested = errors.New("help requested")

// Config is the validated connector configuration.
type Config struct {
	// GatewayURL is the zenfra-api base URL (http/https; the tunnel dial derives ws/wss).
	GatewayURL string
	// BootstrapToken authenticates registration. Never log this.
	BootstrapToken string
	// CABundle optionally pins the trust roots for the gateway leg.
	CABundle string
	// UpstreamCABundle optionally pins the trust roots for the VCS leg. Private
	// VCS is usually signed by an internal CA the system roots do not carry;
	// without this the only alternatives would be skipping verification (never)
	// or reissuing the certificate.
	UpstreamCABundle string
	// InstanceKey is this process's stable self-identifier, defaulting to the hostname.
	InstanceKey string
	// EnrollmentKeyFile is where this instance persists the per-instance key the
	// control plane issues at first registration. With it set, the bootstrap token
	// is used exactly once and revoking this instance is enough to end its access;
	// without it, every restart re-registers with the fleet-wide bootstrap token.
	EnrollmentKeyFile string

	// Vendor and Endpoint must match the connector record or the gateway refuses
	// the tunnel upgrade.
	Vendor   Vendor
	Endpoint string
	// CodeloadEndpoint is the pinned second origin GitHub archive downloads are
	// served from. It defaults to Endpoint, which is where GitHub Enterprise
	// serves /_codeload; a cluster with a separate download host sets it. The
	// connector never derives this host from a redirect it was sent — that would
	// be a free rewrite of where a request lands.
	CodeloadEndpoint string
	// SecretFile holds the upstream VCS credential, read at request time and
	// never sent to the control plane. Required in agent_local mode, forbidden
	// in control_plane mode, where there is no local credential to read.
	SecretFile string
	// CredentialMode picks who holds the upstream credential; agent_local by default.
	CredentialMode CredentialMode

	// AllowedProjects scopes every tunneled request; AllProjects opts out of scoping.
	AllowedProjects []string
	AllProjects     bool
	// PolicyMode picks the enforcement model; allowlist by default.
	PolicyMode PolicyMode

	InteractiveConnections int
	LogLevel               string
	// MetricsAddr optionally serves a Prometheus endpoint on host:port. Empty
	// disables it: the connector runs inside the customer's network, so exposing
	// a listener at all is their decision.
	MetricsAddr string

	// WebhookAddr optionally serves the local webhook endpoint the customer's
	// VCS posts push events to, on host:port. Empty disables push triggers
	// entirely, which is the default: nothing listens unless asked.
	WebhookAddr string
	// WebhookSecretFile holds the shared secret the VCS is configured with. It
	// is required whenever WebhookAddr is set — an unauthenticated listener
	// inside the customer's network would let anything on it trigger runs.
	WebhookSecretFile string
}

// String renders the config for diagnostics with credentials redacted.
func (c *Config) String() string {
	scope := "all-projects"
	if !c.AllProjects {
		scope = fmt.Sprintf("projects=%s", strings.Join(c.AllowedProjects, ","))
	}
	codeload := ""
	if c.CodeloadEndpoint != "" && c.CodeloadEndpoint != c.Endpoint {
		codeload = " codeload=" + c.CodeloadEndpoint
	}
	enrollment := "enrollment-key-file=disabled"
	if c.EnrollmentKeyFile != "" {
		enrollment = "enrollment-key-file=" + c.EnrollmentKeyFile
	}
	metrics := "metrics=disabled"
	if c.MetricsAddr != "" {
		metrics = "metrics=" + c.MetricsAddr
	}
	webhook := "webhook=disabled"
	if c.WebhookAddr != "" {
		webhook = "webhook=" + c.WebhookAddr
	}
	return fmt.Sprintf(
		"gateway=%s vendor=%s endpoint=%s%s instance=%s %s interactive=%d secret-file=%s "+
			"ca-bundle=%s upstream-ca-bundle=%s %s %s %s credential-mode=%s policy-mode=%s",
		c.GatewayURL, c.Vendor, c.Endpoint, codeload, c.InstanceKey, scope,
		c.InteractiveConnections, c.SecretFile, c.CABundle, c.UpstreamCABundle, enrollment, metrics,
		webhook, c.CredentialMode, c.PolicyMode,
	)
}

// Load parses args with environment fallbacks and validates the result. getenv is
// injected so tests need not mutate the process environment; pass os.Getenv.
func Load(args []string, getenv func(string) string) (*Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	cfg := &Config{}
	var allowedProjects string

	fs := flag.NewFlagSet("zenfra-vcs-connector", flag.ContinueOnError)
	// Errors are returned, not printed: the caller decides how to report them, and
	// flag's own output would echo the bootstrap token from the usage defaults.
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.GatewayURL, "gateway-url", getenv(EnvGatewayURL),
		"zenfra-api base URL, e.g. https://api.zenfra.cloud")
	// Registered with an empty default so -h can print the usage without echoing
	// the fleet-wide bootstrap token; the env fallback is applied after Parse.
	fs.StringVar(&cfg.BootstrapToken, "bootstrap-token", "",
		"connector bootstrap token (vcsc_..., or set "+EnvBootstrapToken+")")
	fs.StringVar(&cfg.Endpoint, "endpoint", getenv(EnvEndpoint),
		"upstream VCS base URL, e.g. https://gitlab.internal "+
			"(Azure DevOps: include the collection, e.g. https://tfs.internal/DefaultCollection)")
	fs.StringVar(&cfg.CodeloadEndpoint, "codeload-endpoint", getenv(EnvCodeloadEndpoint),
		"pinned origin serving GitHub archive downloads (default: the endpoint)")
	fs.StringVar((*string)(&cfg.Vendor), "vendor", getenv(EnvVendor),
		"upstream VCS vendor ("+vendorList()+")")
	fs.StringVar(&cfg.SecretFile, "secret-file", getenv(EnvSecretFile),
		"path to the file holding the upstream VCS credential")
	fs.StringVar(&allowedProjects, "allowed-projects", getenv(EnvAllowedProjects),
		"comma-separated project IDs or paths this connector may serve")
	fs.BoolVar(&cfg.AllProjects, "all-projects", getenv(EnvAllProjects) == "true",
		"serve every project the credential can reach instead of an allowlist")
	fs.StringVar((*string)(&cfg.CredentialMode), "credential-mode",
		orDefault(getenv(EnvCredentialMode), string(CredentialModeAgentLocal)),
		"who holds the upstream credential ("+string(CredentialModeAgentLocal)+" or "+
			string(CredentialModeControlPlane)+")")
	fs.StringVar((*string)(&cfg.PolicyMode), "policy-mode",
		orDefault(getenv(EnvPolicyMode), string(PolicyModeAllowlist)),
		"request enforcement model ("+string(PolicyModeAllowlist)+" or "+
			string(PolicyModeBlocklist)+")")
	fs.StringVar(&cfg.InstanceKey, "instance-key", getenv(EnvInstanceKey),
		"stable identifier for this instance (default: hostname)")
	fs.StringVar(&cfg.EnrollmentKeyFile, "enrollment-key-file", getenv(EnvEnrollmentKeyFile),
		"path this instance stores its per-instance enrollment key in (default: disabled)")
	fs.StringVar(&cfg.CABundle, "ca-bundle", getenv(EnvCABundle),
		"PEM bundle of trust roots for the gateway connection (default: system roots)")
	fs.StringVar(&cfg.UpstreamCABundle, "upstream-ca-bundle", getenv(EnvUpstreamCABundle),
		"PEM bundle of trust roots for the upstream VCS (default: system roots)")
	fs.IntVar(&cfg.InteractiveConnections, "interactive-connections",
		intFromEnv(getenv(EnvInteractiveConnections), DefaultInteractiveConnections),
		"number of interactive tunnel streams to maintain")
	fs.StringVar(&cfg.LogLevel, "log-level", orDefault(getenv(EnvLogLevel), "info"),
		"log level (debug, info, warn, error)")
	fs.StringVar(&cfg.MetricsAddr, "metrics-addr", getenv(EnvMetricsAddr),
		"serve Prometheus metrics on this host:port (default: disabled)")
	fs.StringVar(&cfg.WebhookAddr, "webhook-addr", getenv(EnvWebhookAddr),
		"serve the local VCS webhook endpoint on this host:port (default: disabled)")
	fs.StringVar(&cfg.WebhookSecretFile, "webhook-secret-file", getenv(EnvWebhookSecretFile),
		"path to the file holding the webhook shared secret (required with --webhook-addr)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(os.Stdout)
			fmt.Fprintln(os.Stdout, "Usage of zenfra-vcs-connector:") //nolint:errcheck // stdout
			fs.PrintDefaults()
			return nil, ErrHelpRequested
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if cfg.BootstrapToken == "" {
		cfg.BootstrapToken = getenv(EnvBootstrapToken)
	}
	cfg.AllowedProjects = splitList(allowedProjects)

	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// checkRequired verifies every setting that has no usable default.
func (c *Config) checkRequired() error {
	for _, required := range []struct {
		value, flag, env string
	}{
		{c.GatewayURL, "--gateway-url", EnvGatewayURL},
		{c.Endpoint, "--endpoint", EnvEndpoint},
		{string(c.Vendor), "--vendor", EnvVendor},
	} {
		if strings.TrimSpace(required.value) == "" {
			return fmt.Errorf("%w: %s is required (or set %s)",
				ErrInvalidConfig, required.flag, required.env)
		}
	}
	// Once this instance has enrolled it presents its own persisted key, so the
	// fleet-wide bootstrap token can be unmounted — which is the whole point of
	// per-instance enrollment. Demand it only when there is no key to fall back on.
	// Trimmed in place, not just for the emptiness test: a trailing newline from
	// a ConfigMap would otherwise make every open of the key file fail and
	// silently fall back to the fleet-wide bootstrap token.
	c.EnrollmentKeyFile = strings.TrimSpace(c.EnrollmentKeyFile)
	if strings.TrimSpace(c.BootstrapToken) == "" && !c.hasEnrollmentKey() {
		return fmt.Errorf("%w: --bootstrap-token is required (or set %s) "+
			"until this instance has enrolled and persisted an enrollment key",
			ErrInvalidConfig, EnvBootstrapToken)
	}
	return nil
}

// hasEnrollmentKey reports whether a non-empty enrollment key is already on disk.
func (c *Config) hasEnrollmentKey() bool {
	if c.EnrollmentKeyFile == "" {
		return false
	}
	info, err := os.Stat(c.EnrollmentKeyFile)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

// normalizeCredentialMode validates the credential mode and the secret file that
// belongs — or must not belong — to it.
func (c *Config) normalizeCredentialMode() error {
	if c.CredentialMode == "" {
		c.CredentialMode = CredentialModeAgentLocal
	}
	c.SecretFile = strings.TrimSpace(c.SecretFile)
	switch c.CredentialMode {
	case CredentialModeAgentLocal:
		if c.SecretFile == "" {
			return fmt.Errorf("%w: --secret-file is required (or set %s)",
				ErrInvalidConfig, EnvSecretFile)
		}
	case CredentialModeControlPlane:
		if c.SecretFile != "" {
			return fmt.Errorf(
				"%w: --secret-file must not be set with --credential-mode %s: the credential "+
					"arrives over the tunnel, so a local one would never be read",
				ErrInvalidConfig, CredentialModeControlPlane)
		}
	default:
		return fmt.Errorf("%w: --credential-mode %q is not supported, want %s or %s",
			ErrInvalidConfig, c.CredentialMode, CredentialModeAgentLocal, CredentialModeControlPlane)
	}
	return nil
}

// normalizePolicyMode validates the enforcement model. Blocklist mode cannot
// derive a project from a path no rule describes, so it only runs unscoped —
// which is also the honest reading of "allow whatever is not denied".
func (c *Config) normalizePolicyMode() error {
	if c.PolicyMode == "" {
		c.PolicyMode = PolicyModeAllowlist
	}
	switch c.PolicyMode {
	case PolicyModeAllowlist:
		return nil
	case PolicyModeBlocklist:
		if !c.AllProjects {
			return fmt.Errorf(
				"%w: --policy-mode %s requires --all-projects: an unlisted path carries no "+
					"project this connector could scope it by",
				ErrInvalidConfig, PolicyModeBlocklist)
		}
		return nil
	default:
		return fmt.Errorf("%w: --policy-mode %q is not supported, want %s or %s",
			ErrInvalidConfig, c.PolicyMode, PolicyModeAllowlist, PolicyModeBlocklist)
	}
}

// normalize validates every setting and canonicalizes the URLs.
func (c *Config) normalize() error {
	if err := c.checkRequired(); err != nil {
		return err
	}

	if !c.Vendor.supported() {
		return fmt.Errorf("%w: --vendor %q is not supported, want one of %s",
			ErrInvalidConfig, c.Vendor, vendorList())
	}

	gateway, err := canonicalizeURL(c.GatewayURL)
	if err != nil {
		return fmt.Errorf("%w: --gateway-url %w", ErrInvalidConfig, err)
	}
	c.GatewayURL = gateway

	endpoint, err := canonicalizeURL(c.Endpoint)
	if err != nil {
		return fmt.Errorf("%w: --endpoint %w", ErrInvalidConfig, err)
	}
	c.Endpoint = endpoint

	if err := c.normalizeCodeloadEndpoint(); err != nil {
		return err
	}

	if err := c.normalizeCredentialMode(); err != nil {
		return err
	}

	if err := c.normalizeScope(); err != nil {
		return err
	}

	if err := c.normalizePolicyMode(); err != nil {
		return err
	}

	if err := c.normalizeMetricsAddr(); err != nil {
		return err
	}

	return c.normalizeWebhookAddr()
}

// normalizeScope validates the project allowlist, the stream count and the
// instance key — the settings that describe what this instance serves.
func (c *Config) normalizeScope() error {
	switch {
	case c.AllProjects && len(c.AllowedProjects) > 0:
		return fmt.Errorf("%w: --allowed-projects and --all-projects are mutually exclusive",
			ErrInvalidConfig)
	case !c.AllProjects && len(c.AllowedProjects) == 0:
		return fmt.Errorf("%w: --allowed-projects is required unless --all-projects is set",
			ErrInvalidConfig)
	}

	// Bounded at both ends: the gateway caps what one connector may hold, so an
	// unbounded count here would just hammer the control plane with upgrades that
	// are refused on arrival.
	if c.InteractiveConnections < 1 || c.InteractiveConnections > maxInteractiveConnections {
		return fmt.Errorf("%w: --interactive-connections must be between 1 and %d, got %d",
			ErrInvalidConfig, maxInteractiveConnections, c.InteractiveConnections)
	}

	if c.InstanceKey == "" {
		host, hostErr := os.Hostname()
		if hostErr != nil || host == "" {
			return fmt.Errorf("%w: --instance-key is required, hostname unavailable: %w",
				ErrInvalidConfig, hostErr)
		}
		c.InstanceKey = host
	}
	return nil
}

// normalizeMetricsAddr validates the optional metrics listener address. A bad
// address is terminal: binding it later would fail the same way every time.
func (c *Config) normalizeMetricsAddr() error {
	c.MetricsAddr = strings.TrimSpace(c.MetricsAddr)
	if c.MetricsAddr == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(c.MetricsAddr); err != nil {
		return fmt.Errorf("%w: --metrics-addr must be host:port (or set %s): %w",
			ErrInvalidConfig, EnvMetricsAddr, err)
	}
	return nil
}

// normalizeWebhookAddr validates the optional webhook listener address and the
// secret that must come with it.
func (c *Config) normalizeWebhookAddr() error {
	c.WebhookAddr = strings.TrimSpace(c.WebhookAddr)
	c.WebhookSecretFile = strings.TrimSpace(c.WebhookSecretFile)
	if c.WebhookAddr == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(c.WebhookAddr); err != nil {
		return fmt.Errorf("%w: --webhook-addr must be host:port (or set %s): %w",
			ErrInvalidConfig, EnvWebhookAddr, err)
	}
	if c.WebhookSecretFile == "" {
		return fmt.Errorf("%w: --webhook-secret-file is required with --webhook-addr (or set %s)",
			ErrInvalidConfig, EnvWebhookSecretFile)
	}
	return nil
}

// normalizeCodeloadEndpoint validates the pinned archive origin. Only GitHub has
// one; for every other vendor a value is a misunderstanding worth failing on
// rather than silently ignoring.
func (c *Config) normalizeCodeloadEndpoint() error {
	if c.Vendor != VendorGitHub {
		if strings.TrimSpace(c.CodeloadEndpoint) != "" {
			return fmt.Errorf("%w: --codeload-endpoint is only valid with --vendor %s",
				ErrInvalidConfig, VendorGitHub)
		}
		return nil
	}
	if strings.TrimSpace(c.CodeloadEndpoint) == "" {
		c.CodeloadEndpoint = c.Endpoint
		return nil
	}
	codeload, err := canonicalizeURL(c.CodeloadEndpoint)
	if err != nil {
		return fmt.Errorf("%w: --codeload-endpoint %w", ErrInvalidConfig, err)
	}
	c.CodeloadEndpoint = codeload
	return nil
}

// vendorList renders the supported vendors for an error message.
func vendorList() string {
	names := make([]string, 0, len(supportedVendors))
	for _, vendor := range supportedVendors {
		names = append(names, string(vendor))
	}
	return strings.Join(names, ", ")
}

// canonicalizeURL normalizes a base URL the same way the control plane does, so a
// configured endpoint fingerprints identically to the stored connector record.
func canonicalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("is not a valid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("must include a host")
	}
	if u.User != nil {
		return "", errors.New("must not contain userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", errors.New("must not contain a query or fragment")
	}
	p := u.EscapedPath()
	if strings.Contains(p, "%") {
		return "", errors.New("path must not contain percent-encoded characters")
	}
	p = strings.TrimRight(p, "/")
	if p != "" && path.Clean(p) != p {
		return "", errors.New("path must be normalized (no dot or empty segments)")
	}
	return scheme + "://" + strings.ToLower(u.Host) + p, nil
}

// splitList parses a comma-separated list, dropping blank entries.
func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func intFromEnv(raw string, fallback int) int {
	// Atoi, not Sscanf: Sscanf stops at the first non-digit, so "3junk" would
	// silently mean 3 instead of falling back.
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
