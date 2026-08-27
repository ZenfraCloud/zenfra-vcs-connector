// ABOUTME: Header discipline for tunneled requests: what may cross in, what may cross back.
// ABOUTME: Credential-bearing inbound headers are refused; everything unlisted is dropped.
package executor

import (
	"net/http"

	"github.com/ZenfraCloud/zenfra-vcs-connector/internal/config"
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
	"Content-Type":          true,
	"Content-Disposition":   true,
	"Etag":                  true,
	"Last-Modified":         true,
	"Link":                  true,
	"Retry-After":           true,
	"Ratelimit-Limit":       true,
	"Ratelimit-Remaining":   true,
	"Ratelimit-Reset":       true,
	"Ratelimit-Observed":    true,
	"Ratelimit-Resettime":   true,
	"X-Ratelimit-Limit":     true,
	"X-Ratelimit-Remaining": true,
	"X-Ratelimit-Reset":     true,
	"X-Page":                true,
	"X-Next-Page":           true,
	"X-Prev-Page":           true,
	"X-Per-Page":            true,
	"X-Total":               true,
	"X-Total-Pages":         true,
	// Bitbucket Data Center names the authenticated user here on every
	// authenticated response; it has no "current user" endpoint, so this header
	// is what an integration verify observes. It carries no credential.
	"X-Ausername": true,
	// Azure DevOps pages its list resources with a continuation token in this
	// header rather than in the body.
	"X-Ms-Continuationtoken":  true,
	"X-Gitlab-Blob-Id":        true,
	"X-Gitlab-Content-Sha256": true,
	"X-Gitlab-Size":           true,
}

// credentialHeader returns the canonical name of the first credential-bearing
// header found in an inbound request, or "" when there is none. accepted names
// the one header control_plane mode expects to receive; in the default
// agent_local mode it is empty and every credential header is refused.
func credentialHeader(headers map[string]*tunnel.HeaderValues, accepted string) string {
	for name := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if canonical == accepted {
			continue
		}
		if rejectedRequestHeaders[canonical] {
			return canonical
		}
	}
	return ""
}

// vendorCredentialHeader is the header each vendor's credential travels in. It is
// the only inbound credential control_plane mode accepts, and the header the
// credential is injected into in either mode.
func vendorCredentialHeader(vendor config.Vendor) string {
	if vendor == config.VendorGitLab {
		return http.CanonicalHeaderKey(gitLabTokenHeader)
	}
	return gitHubAuthHeader
}

// tunneledCredential returns the value of the accepted credential header, or ""
// when the control plane sent none.
func tunneledCredential(headers map[string]*tunnel.HeaderValues, accepted string) string {
	for name, values := range headers {
		if http.CanonicalHeaderKey(name) != accepted {
			continue
		}
		for _, value := range values.GetValues() {
			if value != "" {
				return value
			}
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
