// ABOUTME: Tests for connector configuration loading from flags and environment.
// ABOUTME: Covers required settings, precedence, project scoping and fatal misconfig messages.
package config

import (
	"errors"
	"strings"
	"testing"
)

// env builds a getenv func over a map so tests never touch the process environment.
func env(pairs map[string]string) func(string) string {
	return func(key string) string { return pairs[key] }
}

// validArgs is a complete, minimal command line.
func validArgs() []string {
	return []string{
		"--gateway-url", "https://api.zenfra.cloud",
		"--bootstrap-token", "vcsc_abc.def",
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
	if cfg.BootstrapToken != "vcsc_abc.def" {
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
		"--bootstrap-token", "vcsc_abc.def",
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
				"--bootstrap-token", "vcsc_abc.def",
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
				"--bootstrap-token", "vcsc_abc.def",
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
				"--bootstrap-token", "vcsc_abc.def",
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
				"--bootstrap-token", "vcsc_abc.def",
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
				"--bootstrap-token", "vcsc_abc.def",
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
				"--bootstrap-token", "vcsc_abc.def",
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
				"--bootstrap-token", "vcsc_abc.def",
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
				"--bootstrap-token", "vcsc_abc.def",
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
				"--bootstrap-token", "vcsc_abc.def",
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
				"--bootstrap-token", "vcsc_abc.def",
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
		"--bootstrap-token", "vcsc_abc.def",
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
