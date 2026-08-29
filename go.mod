module github.com/ZenfraCloud/zenfra-vcs-connector

go 1.26.3

// Build with a toolchain that carries the fixes for GO-2026-6089 (net/http),
// GO-2026-6090 (crypto/tls) and GO-2026-6218 (net/url). The `go` line stays at
// 1.26.3 so consumers are not forced to a newer language version; this only
// raises the toolchain the binary is built with, which is what those advisories
// are about. CI runs govulncheck, so a future stdlib advisory fails the build.
toolchain go1.26.6

require google.golang.org/protobuf v1.36.12

require github.com/gorilla/websocket v1.5.3
