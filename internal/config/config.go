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

// DefaultInteractiveConnections is the interactive stream count per instance; one
// bulk stream is always opened alongside them.
const DefaultInteractiveConnections = 3

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
	EnvInstanceKey            = "ZENFRA_VCS_CONNECTOR_INSTANCE_KEY"
	EnvCABundle               = "ZENFRA_VCS_CONNECTOR_CA_BUNDLE"
	EnvUpstreamCABundle       = "ZENFRA_VCS_CONNECTOR_UPSTREAM_CA_BUNDLE"
	EnvInteractiveConnections = "ZENFRA_VCS_CONNECTOR_INTERACTIVE_CONNECTIONS"
	EnvLogLevel               = "ZENFRA_VCS_CONNECTOR_LOG_LEVEL"
	EnvMetricsAddr            = "ZENFRA_VCS_CONNECTOR_METRICS_ADDR"
)

// ErrInvalidConfig marks a terminal configuration problem. A connector that gets
// one must exit rather than retry: no amount of waiting fixes a bad flag.
var ErrInvalidConfig = errors.New("invalid configuration")

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
	// never sent to the control plane.
	SecretFile string

	// AllowedProjects scopes every tunneled request; AllProjects opts out of scoping.
	AllowedProjects []string
	AllProjects     bool

	InteractiveConnections int
	LogLevel               string
	// MetricsAddr optionally serves a Prometheus endpoint on host:port. Empty
	// disables it: the connector runs inside the customer's network, so exposing
	// a listener at all is their decision.
	MetricsAddr string
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
	metrics := "metrics=disabled"
	if c.MetricsAddr != "" {
		metrics = "metrics=" + c.MetricsAddr
	}
	return fmt.Sprintf(
		"gateway=%s vendor=%s endpoint=%s%s instance=%s %s interactive=%d secret-file=%s "+
			"ca-bundle=%s upstream-ca-bundle=%s %s",
		c.GatewayURL, c.Vendor, c.Endpoint, codeload, c.InstanceKey, scope,
		c.InteractiveConnections, c.SecretFile, c.CABundle, c.UpstreamCABundle, metrics,
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
	fs.StringVar(&cfg.BootstrapToken, "bootstrap-token", getenv(EnvBootstrapToken),
		"connector bootstrap token (vcsc_...)")
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
	fs.StringVar(&cfg.InstanceKey, "instance-key", getenv(EnvInstanceKey),
		"stable identifier for this instance (default: hostname)")
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

	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
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
		{c.BootstrapToken, "--bootstrap-token", EnvBootstrapToken},
		{c.Endpoint, "--endpoint", EnvEndpoint},
		{string(c.Vendor), "--vendor", EnvVendor},
		{c.SecretFile, "--secret-file", EnvSecretFile},
	} {
		if strings.TrimSpace(required.value) == "" {
			return fmt.Errorf("%w: %s is required (or set %s)",
				ErrInvalidConfig, required.flag, required.env)
		}
	}
	return nil
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

	switch {
	case c.AllProjects && len(c.AllowedProjects) > 0:
		return fmt.Errorf("%w: --allowed-projects and --all-projects are mutually exclusive",
			ErrInvalidConfig)
	case !c.AllProjects && len(c.AllowedProjects) == 0:
		return fmt.Errorf("%w: --allowed-projects is required unless --all-projects is set",
			ErrInvalidConfig)
	}

	if c.InteractiveConnections < 1 {
		return fmt.Errorf("%w: --interactive-connections must be at least 1, got %d",
			ErrInvalidConfig, c.InteractiveConnections)
	}

	if err := c.normalizeMetricsAddr(); err != nil {
		return err
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
	var parsed int
	if _, err := fmt.Sscanf(raw, "%d", &parsed); err != nil {
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
