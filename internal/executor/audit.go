// ABOUTME: One structured audit record per tunneled request — decision, rule, status, elapsed.
// ABOUTME: The record has no field that could ever hold a credential, at any log level.
package executor

import (
	"context"
	"log/slog"
	"time"

	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// Audit decision values.
const (
	decisionAllow = "allow"
	decisionDeny  = "deny"
)

// auditRecord is the connector's per-request evidence: what was asked, which rule
// answered, and what happened. Headers and bodies are never fields here, which is
// what makes "no auth material in the log" a property of the type rather than a
// habit of the caller.
type auditRecord struct {
	RequestID string
	Method    string
	Path      string
	Query     string
	Lane      string
	Decision  string
	Rule      string
	Purpose   string
	Project   string
	Status    int
	// Error is the wire error code when the exchange failed.
	Error string
	// Cancelled is the reported CancelAck outcome when the request was cancelled.
	Cancelled string
	// Reason explains a denial or failure in words.
	Reason        string
	RequestBytes  int64
	ResponseBytes int64
}

// log emits exactly one record for the exchange.
func (e *Executor) log(rec *auditRecord, elapsed time.Duration) {
	attrs := []slog.Attr{
		slog.String("request_id", rec.RequestID),
		slog.String("decision", rec.Decision),
		slog.String("method", rec.Method),
		slog.String("path", rec.Path),
		slog.String("lane", rec.Lane),
		slog.Int64("elapsed_ms", elapsed.Milliseconds()),
	}
	for _, opt := range []struct {
		key, value string
	}{
		{"rule", rec.Rule},
		{"purpose", rec.Purpose},
		{"project", rec.Project},
		{"query", rec.Query},
		{"error", rec.Error},
		{"cancelled", rec.Cancelled},
		{"reason", rec.Reason},
	} {
		if opt.value != "" {
			attrs = append(attrs, slog.String(opt.key, opt.value))
		}
	}
	if rec.Status != 0 {
		attrs = append(attrs, slog.Int("status", rec.Status))
	}
	if rec.RequestBytes != 0 {
		attrs = append(attrs, slog.Int64("request_bytes", rec.RequestBytes))
	}
	if rec.ResponseBytes != 0 {
		attrs = append(attrs, slog.Int64("response_bytes", rec.ResponseBytes))
	}

	level := slog.LevelInfo
	if rec.Decision == decisionDeny || rec.Error != "" {
		level = slog.LevelWarn
	}
	// context.Background(): the record must be written even when the request
	// context was cancelled.
	e.audit.LogAttrs(context.Background(), level, "vcs request", attrs...)
}

// laneName renders the deadline class for the audit record.
func laneName(class tunnel.DeadlineClass) string {
	if class == tunnel.DeadlineClass_DEADLINE_CLASS_BULK {
		return "bulk"
	}
	return "interactive"
}
