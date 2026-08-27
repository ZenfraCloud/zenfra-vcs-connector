// ABOUTME: The opt-in blocklist mode's deny table: path segments and methods that stay refused.
// ABOUTME: Best-effort by construction — the allowlist remains the mode that can be reasoned about.
package policy

import (
	"slices"
	"strings"
)

// Rule identifiers reported for a decision blocklist mode made on its own,
// without a compiled rule.
const (
	// RuleUnlisted marks a request no compiled rule describes that blocklist mode
	// let through. It appears in the connector's audit log, so an operator can
	// see exactly what the mode admitted.
	RuleUnlisted = "blocklist.unlisted"
	// RuleDenied marks a request the deny table refused.
	RuleDenied = "blocklist.denied"
)

// purposeUnlisted names the pseudo-operation in the audit log.
const purposeUnlisted = "Unlisted Operation"

// deniedSegments are path segments blocklist mode refuses wherever they appear.
// They cover the administrative, credential and webhook surfaces of the four
// supported vendors: the endpoints that grant access rather than read code.
//
// ponytail: one shared table rather than four vendor tables. The segments do not
// collide across vendors, an extra denial costs an operator one flag-day, and a
// blocklist is best-effort whatever its size — the allowlist is the mode with a
// completeness argument.
var deniedSegments = map[string]bool{
	"admin":                  true,
	"admins":                 true,
	"access_tokens":          true,
	"audit_events":           true,
	"deploy_keys":            true,
	"deploy_tokens":          true,
	"hooks":                  true,
	"keys":                   true,
	"members":                true,
	"permissions":            true,
	"personal_access_tokens": true,
	"runners":                true,
	"scim":                   true,
	"secrets":                true,
	"serviceendpoint":        true,
	"settings":               true,
	"tokens":                 true,
	"users":                  true,
	"variables":              true,
	"webhooks":               true,
}

// deniedMethods are refused in blocklist mode regardless of path. Zenfra issues
// no DELETE against a VCS, so allowing one would only ever serve a mistake.
var deniedMethods = map[string]bool{"DELETE": true}

// blocklistDecide answers a canonical request no compiled rule allowed. It is
// reached only in blocklist mode.
func blocklistDecide(dec *Decision, path, query string) {
	if deniedMethods[dec.Method] {
		dec.RuleID, dec.Reason = RuleDenied,
			"method "+dec.Method+" is never allowed in blocklist mode"
		return
	}
	if segment := deniedSegment(path); segment != "" {
		dec.RuleID = RuleDenied
		dec.Reason = "path segment " + segment + " is on the blocklist mode deny table"
		return
	}
	dec.Allowed = true
	dec.RuleID, dec.Purpose = RuleUnlisted, purposeUnlisted
	dec.Origin = OriginPrimary
	dec.Path, dec.Query = path, query
}

// deniedSegment returns the first deny-table segment in a canonical path, or "".
// Comparison is on the raw segment: an encoded project path is one segment and
// cannot smuggle "admin" past the table as a decoded component.
func deniedSegment(path string) string {
	for _, segment := range strings.Split(path, "/") {
		if lower := strings.ToLower(segment); deniedSegments[lower] {
			return lower
		}
	}
	return ""
}

// denyTableFingerprint renders the deny table for the policy hash, so switching
// modes — or shipping a different table — is visible to the gateway's pin.
func denyTableFingerprint(mode string) string {
	var b strings.Builder
	b.WriteString("mode=" + mode + "\n")
	for _, segment := range sortedKeys(deniedSegments) {
		b.WriteString("deny-segment=" + segment + "\n")
	}
	for _, method := range sortedKeys(deniedMethods) {
		b.WriteString("deny-method=" + method + "\n")
	}
	return b.String()
}

// sortedKeys returns a map's keys in a stable order, so the hash does not depend
// on Go's map iteration.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
