// ABOUTME: Entry point for the customer-run VCS Connector binary.
// ABOUTME: Wires config → policy engine → upstream executor → tunnel connection manager.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/connect"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/executor"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/metrics"
	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/policy"
)

// version is stamped at build time with -ldflags "-X main.version=..." and is
// reported to the control plane at registration.
var version = "dev"

// exitMisconfigured is returned for a terminal configuration problem, which no
// amount of restarting fixes. Distinct from a runtime failure (1) so an
// orchestrator's restart policy can tell "fix your flags" from "try again".
const exitMisconfigured = 2

func main() {
	// main only computes the exit code; every deferred cleanup runs in serve()
	// before os.Exit is reached.
	os.Exit(serve())
}

// serve runs the connector and returns the process exit code.
func serve() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Getenv); err != nil {
		fmt.Fprintf(os.Stderr, "zenfra-vcs-connector: %v\n", err)
		if errors.Is(err, config.ErrInvalidConfig) {
			return exitMisconfigured
		}
		return 1
	}
	return 0
}

// run builds the connector and serves until ctx ends or a terminal error occurs.
// Split out of main so the wiring is testable without spawning a process.
func run(ctx context.Context, args []string, getenv func(string) string) error {
	cfg, err := config.Load(args, getenv)
	if err != nil {
		return err
	}

	logger := newLogger(cfg.LogLevel)
	logger.Info("starting zenfra-vcs-connector", "version", version, "config", cfg.String())

	engine, err := policy.NewEngine(cfg)
	if err != nil {
		return fmt.Errorf("building policy engine: %w", err)
	}
	logger.Info("policy compiled", "rules", len(engine.Rules()), "policy_hash", engine.PolicyHash())

	// The audit logger is the same JSON stream as the operational log: one
	// record per tunneled request, which is the auditable artifact the customer
	// keeps. It is structurally incapable of holding credentials (see audit.go).
	exec, err := executor.New(cfg, engine, logger.With("component", "audit"))
	if err != nil {
		return fmt.Errorf("building executor: %w", err)
	}

	collector := metrics.New(time.Now())
	exec.Metrics = collector
	stopMetrics, err := serveMetrics(cfg.MetricsAddr, collector, logger)
	if err != nil {
		return err
	}
	defer stopMetrics()

	dialer, err := connect.NewDialer(cfg, engine.PolicyHash(), exec.Handler(), logger)
	if err != nil {
		return fmt.Errorf("building tunnel dialer: %w", err)
	}

	manager := connect.NewManager(cfg, connect.NewClient(cfg.GatewayURL, nil), dialer, version, logger)
	manager.Metrics = collector
	if err := manager.Run(ctx); err != nil {
		return fmt.Errorf("tunnel stopped: %w", err)
	}
	logger.Info("zenfra-vcs-connector stopped")
	return nil
}

// serveMetrics starts the optional Prometheus endpoint and returns its shutdown.
// The listener is opened synchronously so an unusable address fails startup
// instead of silently never serving.
func serveMetrics(
	addr string,
	collector *metrics.Collector,
	logger *slog.Logger,
) (func(), error) {
	if addr == "" {
		return func() {}, nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: --metrics-addr %s: %w", config.ErrInvalidConfig, addr, err)
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", collector.Handler())
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if serveErr := srv.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error("metrics endpoint stopped", "error", serveErr)
		}
	}()
	logger.Info("metrics endpoint listening", "addr", listener.Addr().String())

	return func() { _ = srv.Close() }, nil
}

// newLogger builds the structured JSON logger. Output is stderr so a container's
// stdout stays free for anything an operator pipes.
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
