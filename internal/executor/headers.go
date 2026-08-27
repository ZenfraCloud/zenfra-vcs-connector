// ABOUTME: Header discipline for tunneled requests: what may cross in, what may cross back.
// ABOUTME: Credential-bearing inbound headers are refused; everything unlisted is dropped.
package executor

import (
	"net/http"

	"github.com/ZenfraCloud/zenfra-vcs-connector/tunnel"
)

// rejectedRequestHeaders are refused outright rather than dropped. The control
// plane holds no credential for this upstream, so one arriving over the tunnel
// means something is wrong and the request must not be laundered into a valid
// call by silently stripping it.
var rejectedRequestHeaders = map[string]bool{
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              true,
	"Private-Token":       true,
	"Job-Token":           true,
	"Deploy-Token":        true,
	"X-Api-Key":           true,
	"X-Access-Token":      true,
	"X-Csrf-Token":        true,
}

// forwardableRequestHeaders is the entire set that crosses to the upstream.
// Anything else — hop-by-hop headers, forwarding headers, the caller's own
// User-Agent — is dropped, so the upstream sees a request shaped by this
// connector and nothing it was told to say.
var forwardableRequestHeaders = map[string]bool{
	"Accept":       true,
	"Content-Type": true,
	// GitHub's API version pin. Dropping it would silently serve whatever the
	// upstream defaults to, which is the version negotiation the caller opted out of.
	"X-Github-Api-Version": true,
}

// forwardableResponseHeaders is what travels back. Set-Cookie and every
// authentication header are absent by construction: the tunnel must not carry an
// upstream session into the control plane.
var forwardableResponseHeaders = map[string]bool{
	"Content-Type":            true,
	"Content-Disposition":     true,
	"Etag":                    true,
	"Last-Modified":           true,
	"Link":                    true,
	"Retry-After":             true,
	"Ratelimit-Limit":         true,
	"Ratelimit-Remaining":     true,
	"Ratelimit-Reset":         true,
	"Ratelimit-Observed":      true,
	"Ratelimit-Resettime":     true,
	"X-Ratelimit-Limit":       true,
	"X-Ratelimit-Remaining":   true,
	"X-Ratelimit-Reset":       true,
	"X-Page":                  true,
	"X-Next-Page":             true,
	"X-Prev-Page":             true,
	"X-Per-Page":              true,
	"X-Total":                 true,
	"X-Total-Pages":           true,
	"X-Gitlab-Blob-Id":        true,
	"X-Gitlab-Content-Sha256": true,
	"X-Gitlab-Size":           true,
}

// credentialHeader returns the canonical name of the first credential-bearing
// header found in an inbound request, or "" when there is none.
func credentialHeader(headers map[string]*tunnel.HeaderValues) string {
	for name := range headers {
		if canonical := http.CanonicalHeaderKey(name); rejectedRequestHeaders[canonical] {
			return canonical
		}
	}
	return ""
}

// filterResponseHeaders copies the allowlisted response headers.
//
// Content-Length is deliberately never forwarded: the body's length on the
// tunnel is defined by its terminal chunk, and Go's transparent gzip can leave
// the upstream value describing bytes the consumer will never see.
func filterResponseHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for name, values := range h {
		if !forwardableResponseHeaders[http.CanonicalHeaderKey(name)] {
			continue
		}
		out[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
	}
	return out
}
