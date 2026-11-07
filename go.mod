module github.com/ZenfraCloud/zenfra-vcs-connector

go 1.26.3

// Build with a toolchain that carries the standard library security fixes
// govulncheck reports (1.26.10: GO-2026-6809 in crypto/x509; 1.26.9:
// GO-2026-6603..6617 in net/http, crypto/tls and net/textproto). The `go` line
// stays at 1.26.3 so consumers are not forced to a newer language version; this
// only raises the toolchain the binary is built with, which is what those
// advisories are about. CI runs govulncheck, so a future stdlib advisory fails
// the build.
toolchain go1.26.10

require google.golang.org/protobuf v1.36.12

require github.com/gorilla/websocket v1.5.3
