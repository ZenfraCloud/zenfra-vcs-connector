// ABOUTME: Tests for connector configuration loading from flags and environment.
// ABOUTME: Covers required settings, precedence, project scoping and fatal misconfig messages.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// env builds a getenv func over a map so tests never touch the process environment.
func env(pairs map[string]string) func(string) string {
	return func(key string) string { return pairs[key] }
}

// testBootstrapToken is the bootstrap token every fixture command line carries.
const testBootstrapToken = "vcsc_abc.def"

// validArgs is a complete, minimal command line.
func validArgs() []string {
	return []string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", testBootstrapToken,
		"--endpoint", "https://gitlab.internal",
		"--vendor", "gitlab",
		"--secret-file", "/etc/zenfra/gitlab-token",
		"--allowed-projects", "42,eng/platform",
	}
}

func TestLoadValidConfig(t *testing.T) {
	cfg, err := Load(validArgs(), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.GatewayURL != "https://api.zenfra.cloud" {
		t.Errorf("GatewayURL = %q", cfg.GatewayURL)
	}
	if cfg.BootstrapToken != testBootstrapToken {
		t.Errorf("BootstrapToken = %q", cfg.BootstrapToken)
	}
	if cfg.Endpoint != "https://gitlab.internal" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
	if cfg.Vendor != VendorGitLab {
		t.Errorf("Vendor = %q", cfg.Vendor)
	}
	if cfg.SecretFile != "/etc/zenfra/gitlab-token" {
		t.Errorf("SecretFile = %q", cfg.SecretFile)
	}
	if got, want := cfg.AllowedProjects, []string{"42", "eng/platform"}; !equalStrings(got, want) {
		t.Errorf("AllowedProjects = %v, want %v", got, want)
	}
	if cfg.AllProjects {
		t.Error("AllProjects = true, want false")
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(validArgs(), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.InteractiveConnections != DefaultInteractiveConnections {
		t.Errorf("InteractiveConnections = %d, want %d",
			cfg.InteractiveConnections, DefaultInteractiveConnections)
	}
	if cfg.InstanceKey == "" {
		t.Error("InstanceKey is empty, want a hostname-derived default")
	}
	if cfg.CABundle != "" {
		t.Errorf("CABundle = %q, want empty (system roots)", cfg.CABundle)
	}
}

func TestLoadTrimsEndpointTrailingSlash(t *testing.T) {
	args := append(validArgs(), "--endpoint", "https://GitLab.Internal:8443/gitlab/")
	cfg, err := Load(args, env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if want := "https://gitlab.internal:8443/gitlab"; cfg.Endpoint != want {
		t.Errorf("Endpoint = %q, want %q", cfg.Endpoint, want)
	}
}

func TestLoadReadsEnvironment(t *testing.T) {
	cfg, err := Load(nil, env(map[string]string{
		EnvGatewayURL:       "https://api.zenfra.cloud",
		EnvBootstrapToken:   "vcsc_abc.def",
		EnvEndpoint:         "https://gitlab.internal",
		EnvVendor:           "gitlab",
		EnvSecretFile:       "/run/secrets/token",
		EnvAllowedProjects:  "42, eng/platform ,,",
		EnvInstanceKey:      "connector-0",
		EnvCABundle:         "/etc/ssl/corp.pem",
		EnvUpstreamCABundle: "/etc/ssl/internal-ca.pem",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SecretFile != "/run/secrets/token" {
		t.Errorf("SecretFile = %q", cfg.SecretFile)
	}
	if cfg.InstanceKey != "connector-0" {
		t.Errorf("InstanceKey = %q", cfg.InstanceKey)
	}
	if cfg.CABundle != "/etc/ssl/corp.pem" {
		t.Errorf("CABundle = %q", cfg.CABundle)
	}
	// The two legs carry separate trust: the gateway is public, the VCS is not.
	if cfg.UpstreamCABundle != "/etc/ssl/internal-ca.pem" {
		t.Errorf("UpstreamCABundle = %q", cfg.UpstreamCABundle)
	}
	if got, want := cfg.AllowedProjects, []string{"42", "eng/platform"}; !equalStrings(got, want) {
		t.Errorf("AllowedProjects = %v, want %v (blank entries dropped)", got, want)
	}
}

func TestLoadFlagsOverrideEnvironment(t *testing.T) {
	cfg, err := Load([]string{"--secret-file", "/from/flag"}, env(map[string]string{
		EnvGatewayURL:      "https://api.zenfra.cloud",
		EnvBootstrapToken:  "vcsc_abc.def",
		EnvEndpoint:        "https://gitlab.internal",
		EnvVendor:          "gitlab",
		EnvSecretFile:      "/from/env",
		EnvAllowedProjects: "42",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SecretFile != "/from/flag" {
		t.Errorf("SecretFile = %q, want the flag value", cfg.SecretFile)
	}
}

func TestLoadAllProjects(t *testing.T) {
	args := []string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", testBootstrapToken,
		"--endpoint", "https://gitlab.internal",
		"--vendor", "gitlab",
		"--secret-file", "/etc/zenfra/gitlab-token",
		"--all-projects",
	}
	cfg, err := Load(args, env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.AllProjects {
		t.Error("AllProjects = false, want true")
	}
	if len(cfg.AllowedProjects) != 0 {
		t.Errorf("AllowedProjects = %v, want empty", cfg.AllowedProjects)
	}
}

func TestLoadMisconfigIsFatalWithClearMessage(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
		// want appears in the error message so an operator can fix it without
		// reading the source.
		want []string
	}{
		{
			name: "missing bootstrap token",
			args: []string{
				"--gateway-url", "https://api.zenfra.cloud",
				"--endpoint", "https://gitlab.internal",
				"--vendor", "gitlab",
				"--secret-file", "/etc/zenfra/gitlab-token",
				"--all-projects",
			},
			want: []string{"--bootstrap-token", EnvBootstrapToken},
		},
		{
			name: "missing gateway url",
			args: []string{
				"--bootstrap-token", testBootstrapToken,
				"--endpoint", "https://gitlab.internal",
				"--vendor", "gitlab",
				"--secret-file", "/etc/zenfra/gitlab-token",
				"--all-projects",
			},
			want: []string{"--gateway-url", EnvGatewayURL},
		},
		{
			name: "missing endpoint",
			args: []string{
				"--gateway-url", "https://api.zenfra.cloud",
				"--bootstrap-token", testBootstrapToken,
				"--vendor", "gitlab",
				"--secret-file", "/etc/zenfra/gitlab-token",
				"--all-projects",
			},
			want: []string{"--endpoint", EnvEndpoint},
		},
		{
			name: "missing vendor",
			args: []string{
				"--gateway-url", "https://api.zenfra.cloud",
				"--bootstrap-token", testBootstrapToken,
				"--endpoint", "https://gitlab.internal",
				"--secret-file", "/etc/zenfra/gitlab-token",
				"--all-projects",
			},
			want: []string{"--vendor", EnvVendor},
		},
		{
			name: "unsupported vendor",
			args: []string{
				"--gateway-url", "https://api.zenfra.cloud",
				"--bootstrap-token", testBootstrapToken,
				"--endpoint", "https://gitlab.internal",
				"--vendor", "perforce",
				"--secret-file", "/etc/zenfra/gitlab-token",
				"--all-projects",
			},
			want: []string{
				"--vendor", "perforce",
				string(VendorGitLab), string(VendorGitHub), string(VendorBitbucket),
			},
		},
		{
			name: "missing secret file",
			args: []string{
				"--gateway-url", "https://api.zenfra.cloud",
				"--bootstrap-token", testBootstrapToken,
				"--endpoint", "https://gitlab.internal",
				"--vendor", "gitlab",
				"--all-projects",
			},
			want: []string{"--secret-file", EnvSecretFile},
		},
		{
			name: "project scope unset",
			args: []string{
				"--gateway-url", "https://api.zenfra.cloud",
				"--bootstrap-token", testBootstrapToken,
				"--endpoint", "https://gitlab.internal",
				"--vendor", "gitlab",
				"--secret-file", "/etc/zenfra/gitlab-token",
			},
			want: []string{"--allowed-projects", "--all-projects"},
		},
		{
			name: "project scope both",
			args: append(validArgs(), "--all-projects"),
			want: []string{"--allowed-projects", "--all-projects", "mutually exclusive"},
		},
		{
			name: "gateway url not http",
			args: []string{
				"--gateway-url", "wss://api.zenfra.cloud",
				"--bootstrap-token", testBootstrapToken,
				"--endpoint", "https://gitlab.internal",
				"--vendor", "gitlab",
				"--secret-file", "/etc/zenfra/gitlab-token",
				"--all-projects",
			},
			want: []string{"--gateway-url", "http"},
		},
		{
			name: "endpoint without host",
			args: []string{
				"--gateway-url", "https://api.zenfra.cloud",
				"--bootstrap-token", testBootstrapToken,
				"--endpoint", "https:///api",
				"--vendor", "gitlab",
				"--secret-file", "/etc/zenfra/gitlab-token",
				"--all-projects",
			},
			want: []string{"--endpoint", "host"},
		},
		{
			name: "endpoint with userinfo",
			args: []string{
				"--gateway-url", "https://api.zenfra.cloud",
				"--bootstrap-token", testBootstrapToken,
				"--endpoint", "https://user:pass@gitlab.internal",
				"--vendor", "gitlab",
				"--secret-file", "/etc/zenfra/gitlab-token",
				"--all-projects",
			},
			want: []string{"--endpoint", "userinfo"},
		},
		{
			name: "endpoint with query",
			args: []string{
				"--gateway-url", "https://api.zenfra.cloud",
				"--bootstrap-token", testBootstrapToken,
				"--endpoint", "https://gitlab.internal/?a=b",
				"--vendor", "gitlab",
				"--secret-file", "/etc/zenfra/gitlab-token",
				"--all-projects",
			},
			want: []string{"--endpoint"},
		},
		{
			name: "non positive interactive connections",
			args: append(validArgs(), "--interactive-connections", "0"),
			want: []string{"--interactive-connections"},
		},
		{
			name: "unknown flag",
			args: append(validArgs(), "--nope"),
			want: []string{"nope"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(tt.args, env(tt.env))
			if err == nil {
				t.Fatalf("Load() error = nil, want a fatal config error (cfg = %+v)", cfg)
			}
			// Misconfig is terminal: never retried, so callers can exit on it.
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("errors.Is(err, ErrInvalidConfig) = false, err = %v", err)
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err.Error(), want)
				}
			}
		})
	}
}

func TestLoadNeverEchoesTheBootstrapToken(t *testing.T) {
	const token = "vcsc_abc.supersecret" //nolint:gosec // test fixture, not a real credential
	args := []string{
		"--gateway-url", "wss://bad",
		"--bootstrap-token", token,
		"--endpoint", "https://gitlab.internal",
		"--vendor", "gitlab",
		"--secret-file", "/etc/zenfra/gitlab-token",
		"--all-projects",
	}
	_, err := Load(args, env(nil))
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	if strings.Contains(err.Error(), "supersecret") {
		t.Errorf("error leaks the bootstrap token: %q", err.Error())
	}
}

func TestConfigRedactsTokenInString(t *testing.T) {
	cfg, err := Load(validArgs(), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	s := cfg.String()
	if strings.Contains(s, "def") {
		t.Errorf("String() leaks token material: %q", s)
	}
	if !strings.Contains(s, "gitlab.internal") {
		t.Errorf("String() = %q, want the endpoint for diagnostics", s)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// githubArgs is a complete GitHub Enterprise command line.
func githubArgs(extra ...string) []string {
	return append([]string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", testBootstrapToken,
		"--endpoint", "https://ghe.internal",
		"--vendor", "github",
		"--secret-file", "/etc/zenfra/ghe-token",
		"--all-projects",
	}, extra...)
}

func TestLoadAcceptsGitHubEnterpriseVendor(t *testing.T) {
	cfg, err := Load(githubArgs(), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Vendor != VendorGitHub {
		t.Errorf("Vendor = %q, want %q", cfg.Vendor, VendorGitHub)
	}
	// An unset codeload endpoint means the archive origin is the primary host,
	// which is how GitHub Enterprise serves /_codeload by default.
	if cfg.CodeloadEndpoint != cfg.Endpoint {
		t.Errorf("CodeloadEndpoint = %q, want it to default to the endpoint %q",
			cfg.CodeloadEndpoint, cfg.Endpoint)
	}
}

func TestLoadCanonicalizesCodeloadEndpoint(t *testing.T) {
	cfg, err := Load(githubArgs("--codeload-endpoint", "https://Codeload.GHE.Internal:8443/"), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if want := "https://codeload.ghe.internal:8443"; cfg.CodeloadEndpoint != want {
		t.Errorf("CodeloadEndpoint = %q, want %q", cfg.CodeloadEndpoint, want)
	}
}

func TestLoadReadsCodeloadEndpointFromEnvironment(t *testing.T) {
	cfg, err := Load(githubArgs(), env(map[string]string{
		EnvCodeloadEndpoint: "https://codeload.ghe.internal",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if want := "https://codeload.ghe.internal"; cfg.CodeloadEndpoint != want {
		t.Errorf("CodeloadEndpoint = %q, want %q", cfg.CodeloadEndpoint, want)
	}
}

func TestLoadCodeloadMisconfigIsFatal(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "codeload endpoint on a vendor without one",
			args: append(validArgs(), "--codeload-endpoint", "https://codeload.internal"),
			want: []string{"--codeload-endpoint", string(VendorGitHub)},
		},
		{
			name: "codeload endpoint is not a URL",
			args: githubArgs("--codeload-endpoint", "codeload.ghe.internal"),
			want: []string{"--codeload-endpoint", "scheme"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.args, env(nil))
			if err == nil {
				t.Fatal("Load() error = nil, want a terminal config error")
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("Load() error = %v, want ErrInvalidConfig", err)
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Load() error = %q, want it to mention %q", err, want)
				}
			}
		})
	}
}

func TestConfigStringNamesTheCodeloadEndpoint(t *testing.T) {
	cfg, err := Load(githubArgs("--codeload-endpoint", "https://codeload.ghe.internal"), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !strings.Contains(cfg.String(), "codeload=https://codeload.ghe.internal") {
		t.Errorf("String() = %q, want it to name the codeload endpoint", cfg.String())
	}
}

func TestLoadMetricsAddr(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		getenv  func(string) string
		want    string
		wantErr bool
	}{
		{
			name:   "disabled by default",
			args:   validArgs(),
			getenv: env(nil),
			want:   "",
		},
		{
			name:   "flag sets the listener",
			args:   append(validArgs(), "--metrics-addr", "127.0.0.1:9101"),
			getenv: env(nil),
			want:   "127.0.0.1:9101",
		},
		{
			name:   "environment fallback",
			args:   validArgs(),
			getenv: env(map[string]string{EnvMetricsAddr: ":9101"}),
			want:   ":9101",
		},
		{
			name:    "a non host:port address is terminal",
			args:    append(validArgs(), "--metrics-addr", "9101"),
			getenv:  env(nil),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(tt.args, tt.getenv)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("Load() error = %v, want ErrInvalidConfig", err)
				}
				if !strings.Contains(err.Error(), "--metrics-addr") ||
					!strings.Contains(err.Error(), EnvMetricsAddr) {
					t.Fatalf("error must name both the flag and the env var: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.MetricsAddr != tt.want {
				t.Fatalf("MetricsAddr = %q, want %q", cfg.MetricsAddr, tt.want)
			}
		})
	}
}

func TestConfigStringReportsMetricsState(t *testing.T) {
	cfg, err := Load(validArgs(), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !strings.Contains(cfg.String(), "metrics=disabled") {
		t.Errorf("String() should say metrics are off: %s", cfg.String())
	}

	cfg, err = Load(append(validArgs(), "--metrics-addr", "127.0.0.1:9101"), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !strings.Contains(cfg.String(), "metrics=127.0.0.1:9101") {
		t.Errorf("String() should name the metrics listener: %s", cfg.String())
	}
}

func TestLoadEnrollmentKeyFile(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		getenv func(string) string
		want   string
	}{
		{
			name:   "disabled by default",
			args:   validArgs(),
			getenv: env(nil),
			want:   "",
		},
		{
			name:   "flag sets the path",
			args:   append(validArgs(), "--enrollment-key-file", "/var/lib/zenfra/enrollment-key"),
			getenv: env(nil),
			want:   "/var/lib/zenfra/enrollment-key",
		},
		{
			name:   "environment fallback",
			args:   validArgs(),
			getenv: env(map[string]string{EnvEnrollmentKeyFile: "/state/enrollment-key"}),
			want:   "/state/enrollment-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(tt.args, tt.getenv)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.EnrollmentKeyFile != tt.want {
				t.Fatalf("EnrollmentKeyFile = %q, want %q", cfg.EnrollmentKeyFile, tt.want)
			}
		})
	}
}

func TestConfigStringReportsEnrollmentState(t *testing.T) {
	cfg, err := Load(validArgs(), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !strings.Contains(cfg.String(), "enrollment-key-file=disabled") {
		t.Errorf("String() = %q, want the disabled enrollment state", cfg.String())
	}

	cfg, err = Load(append(validArgs(), "--enrollment-key-file", "/state/enrollment-key"), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !strings.Contains(cfg.String(), "enrollment-key-file=/state/enrollment-key") {
		t.Errorf("String() = %q, want the configured key path", cfg.String())
	}
}

func TestLoadWebhookAddr(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		getenv  func(string) string
		want    string
		wantErr string
	}{
		{
			name:   "disabled by default",
			args:   validArgs(),
			getenv: env(nil),
			want:   "",
		},
		{
			name:   "flag sets the listener",
			args:   append(validArgs(), "--webhook-addr", "0.0.0.0:9000", "--webhook-secret-file", "/secrets/hook"),
			getenv: env(nil),
			want:   "0.0.0.0:9000",
		},
		{
			name: "environment fallback",
			args: validArgs(),
			getenv: env(map[string]string{
				EnvWebhookAddr:       ":9000",
				EnvWebhookSecretFile: "/secrets/hook",
			}),
			want: ":9000",
		},
		{
			name:    "a non host:port address is terminal",
			args:    append(validArgs(), "--webhook-addr", "9000", "--webhook-secret-file", "/secrets/hook"),
			getenv:  env(nil),
			wantErr: "--webhook-addr",
		},
		{
			name:    "a listener without a secret is terminal",
			args:    append(validArgs(), "--webhook-addr", "0.0.0.0:9000"),
			getenv:  env(nil),
			wantErr: "--webhook-secret-file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(tt.args, tt.getenv)
			if tt.wantErr != "" {
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("Load() error = %v, want ErrInvalidConfig", err)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error must name %s: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.WebhookAddr != tt.want {
				t.Fatalf("WebhookAddr = %q, want %q", cfg.WebhookAddr, tt.want)
			}
		})
	}
}

// The secret file path must never be echoed alongside a listener that is off,
// and an enabled listener must be visible in the startup line.
func TestConfigStringReportsWebhookState(t *testing.T) {
	off, err := Load(validArgs(), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !strings.Contains(off.String(), "webhook=disabled") {
		t.Errorf("String() = %q, want webhook=disabled", off.String())
	}

	on, err := Load(append(validArgs(),
		"--webhook-addr", "0.0.0.0:9000", "--webhook-secret-file", "/secrets/hook"), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !strings.Contains(on.String(), "webhook=0.0.0.0:9000") {
		t.Errorf("String() = %q, want the webhook address", on.String())
	}
}

func TestLoadDefaultsToAgentLocalCredentialMode(t *testing.T) {
	cfg, err := Load(validArgs(), env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.CredentialMode != CredentialModeAgentLocal {
		t.Errorf("CredentialMode = %q, want %q", cfg.CredentialMode, CredentialModeAgentLocal)
	}
	if cfg.PolicyMode != PolicyModeAllowlist {
		t.Errorf("PolicyMode = %q, want %q", cfg.PolicyMode, PolicyModeAllowlist)
	}
}

func TestLoadControlPlaneCredentialModeNeedsNoSecretFile(t *testing.T) {
	cfg, err := Load([]string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", testBootstrapToken,
		"--endpoint", "https://gitlab.internal",
		"--vendor", "gitlab",
		"--allowed-projects", "eng/platform",
		"--credential-mode", "control_plane",
	}, env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.CredentialMode != CredentialModeControlPlane {
		t.Errorf("CredentialMode = %q", cfg.CredentialMode)
	}
	if !strings.Contains(cfg.String(), "credential-mode=control_plane") {
		t.Errorf("String() = %q, want it to name the credential mode", cfg.String())
	}
}

func TestLoadControlPlaneCredentialModeRejectsSecretFile(t *testing.T) {
	_, err := Load(append(validArgs(), "--credential-mode", "control_plane"), env(nil))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Load() error = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "--secret-file") {
		t.Errorf("error = %q, want it to name --secret-file", err)
	}
}

func TestLoadRejectsUnknownCredentialMode(t *testing.T) {
	_, err := Load(append(validArgs(), "--credential-mode", "whatever"), env(nil))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Load() error = %v, want ErrInvalidConfig", err)
	}
}

func TestLoadCredentialModeFromEnv(t *testing.T) {
	cfg, err := Load([]string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", testBootstrapToken,
		"--endpoint", "https://gitlab.internal",
		"--vendor", "gitlab",
		"--allowed-projects", "eng/platform",
	}, env(map[string]string{EnvCredentialMode: "control_plane"}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.CredentialMode != CredentialModeControlPlane {
		t.Errorf("CredentialMode = %q", cfg.CredentialMode)
	}
}

func TestLoadAgentLocalStillRequiresSecretFile(t *testing.T) {
	_, err := Load([]string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", testBootstrapToken,
		"--endpoint", "https://gitlab.internal",
		"--vendor", "gitlab",
		"--allowed-projects", "eng/platform",
	}, env(nil))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Load() error = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "--secret-file") {
		t.Errorf("error = %q, want it to name --secret-file", err)
	}
}

func TestLoadBlocklistPolicyModeRequiresAllProjects(t *testing.T) {
	_, err := Load(append(validArgs(), "--policy-mode", "blocklist"), env(nil))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Load() error = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "--all-projects") {
		t.Errorf("error = %q, want it to name --all-projects", err)
	}
}

func TestLoadBlocklistPolicyMode(t *testing.T) {
	cfg, err := Load([]string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", testBootstrapToken,
		"--endpoint", "https://gitlab.internal",
		"--vendor", "gitlab",
		"--secret-file", "/etc/zenfra/gitlab-token",
		"--all-projects",
		"--policy-mode", "blocklist",
	}, env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.PolicyMode != PolicyModeBlocklist {
		t.Errorf("PolicyMode = %q", cfg.PolicyMode)
	}
	if !strings.Contains(cfg.String(), "policy-mode=blocklist") {
		t.Errorf("String() = %q, want it to name the policy mode", cfg.String())
	}
}

func TestLoadRejectsUnknownPolicyMode(t *testing.T) {
	_, err := Load(append(validArgs(), "--policy-mode", "yolo"), env(nil))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Load() error = %v, want ErrInvalidConfig", err)
	}
}

// README tells customers to run --help; it must print the flags and exit 0
// rather than surface as a misconfiguration. It must also not echo the
// fleet-wide bootstrap token from the environment into the usage defaults.
func TestLoadHelpIsNotAMisconfiguration(t *testing.T) {
	getenv := func(key string) string {
		if key == EnvBootstrapToken {
			return "vcsc_leak.secret"
		}
		return ""
	}
	_, err := Load([]string{"--help"}, getenv)
	if !errors.Is(err, ErrHelpRequested) {
		t.Fatalf("Load(--help) error = %v, want ErrHelpRequested", err)
	}
	if errors.Is(err, ErrInvalidConfig) {
		t.Error("help is reported as a misconfiguration, which exits 2")
	}
}

// The env fallback still applies when the flag is absent.
func TestLoadBootstrapTokenFallsBackToTheEnvironment(t *testing.T) {
	args := []string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--endpoint", "https://gitlab.internal",
		"--vendor", "gitlab",
		"--secret-file", "/etc/zenfra/gitlab-token",
		"--all-projects",
	}
	cfg, err := Load(args, func(key string) string {
		if key == EnvBootstrapToken {
			return testBootstrapToken
		}
		return ""
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.BootstrapToken != testBootstrapToken {
		t.Errorf("BootstrapToken = %q, want the environment value", cfg.BootstrapToken)
	}
}

// Task 20's point: once an instance has enrolled it presents its own key, so the
// fleet-wide bootstrap token can be unmounted instead of living on every host.
func TestBootstrapTokenOptionalOnceEnrolled(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "enrollment.key")
	base := []string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--endpoint", "https://gitlab.internal",
		"--vendor", "gitlab",
		"--secret-file", "/etc/zenfra/gitlab-token",
		"--all-projects",
		"--enrollment-key-file", keyFile,
	}

	if _, err := Load(base, env(nil)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("without a stored key the bootstrap token is still required, got %v", err)
	}

	if err := os.WriteFile(keyFile, []byte("vcsk_stored"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(base, env(nil)); err != nil {
		t.Fatalf("a stored enrollment key should stand in for the bootstrap token: %v", err)
	}
}
