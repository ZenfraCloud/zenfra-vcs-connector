# Optional modes: control-plane credentials and blocklist policy

Both modes on this page are **off by default**, must be turned on explicitly on
*both* sides (Zenfra and the connector), and each gives up a property the
connector otherwise guarantees. The defaults — `agent_local` credentials and the
compiled allowlist — are what the security model in the customer docs describes.
Turn a mode on only if you have read what it costs.

## 1. `credential_mode: control_plane`

**Default:** `agent_local`. The upstream VCS credential lives in a file inside
your network, the connector reads it after policy approval, and Zenfra never
holds it. A credential arriving over the tunnel is refused.

**Opt-in:** Zenfra stores the credential (encrypted, per-organization envelope
encryption) and sends it through the tunnel on every request; the connector
forwards it upstream instead of reading a local file.

### What you give up — the exposure trade-off

- **The token leaves your network.** It is stored by Zenfra and travels over the
  tunnel on every tunneled request. "Token stays home", the property that makes a
  compromised control plane unable to exfiltrate your VCS credential, no longer
  holds.
- **A TLS-intercepting proxy on the egress path sees it.** Appliances that
  terminate and re-sign the gateway leg (Zscaler, Netskope, Palo Alto decrypt
  policies) can retain the credential from the WebSocket payload.
- **A compromised or malicious Zenfra control plane gains your VCS credential**,
  not just the ability to observe and forge tunneled requests. That is a strictly
  larger blast radius, and it is the reason this mode is not the default.
- **Rotation moves to Zenfra.** Rotating the PAT in your secret manager is no
  longer enough; the stored copy must be updated too.

What does *not* change: the connector still enforces its policy first, still
refuses cookies and proxy credentials, still never follows an unpinned redirect,
and still logs one audit record per request with no credential in it.

### Enabling it

Connector (both flags, or their `ZENFRA_VCS_CONNECTOR_*` env equivalents):

```
--credential-mode control_plane     # default: agent_local, GitLab only
# --secret-file must NOT be set: there is no local credential to read
```

GitLab is the only vendor this mode supports — it is the only credential Zenfra
stores. The connector refuses to start with any other `--vendor`, rather than
accepting an `Authorization` header off the tunnel and replaying it upstream.

The connector prints a startup warning naming the mode. An instance left on the
default refuses an injected credential with a `protocol` error, so switching
Zenfra alone changes nothing — which is the point.

Zenfra, when creating the integration:

```json
{
  "provider": "gitlab",
  "transport": "connector",
  "vcs_connector_id": "…",
  "credential_mode": "control_plane",
  "gitlab": { "access_token": "glpat-…" }
}
```

Supported for **GitLab only** — it is the one provider Zenfra stores a credential
for. GitHub Enterprise, Bitbucket Data Center and Azure DevOps Server are
`agent_local` always.

## 2. `--policy-mode blocklist`

**Default:** `allowlist`. Only the operations compiled into the connector reach
your VCS; everything else is denied, and the compiled table is auditable in the
open-source binary you run.

**Opt-in:** anything the compiled allowlist does not describe is *allowed* unless
it hits a small deny table (administrative, credential, webhook and member
surfaces, plus every `DELETE`).

### What you give up

- **There is no longer a bounded list of what Zenfra can ask your VCS to do.** A
  future Zenfra release, or a compromised control plane, can call endpoints
  nobody reviewed.
- **The deny table is best-effort and always will be.** It matches path segments;
  a vendor endpoint that grants access under a name not on the list is allowed.
  A blocklist cannot be complete — that is the structural argument for the
  allowlist, not a gap to be closed by adding entries.
- **Project scoping does not apply to unlisted paths**, so the mode requires
  `--all-projects`. The connector refuses to start otherwise.
- **The deny table is consulted on the percent-decoded form, component by
  component.** An upstream that decodes `%2F` before it routes would otherwise
  reach `admin%2Fci%2Fvariables` with the table never checked. The cost is a
  false positive: a group or project whose name is itself a deny word — a
  namespace literally called `admin`, `users` or `hooks` — is refused even
  when it appears URL-encoded in a legitimate project path. Use the default
  allowlist mode if you have one.

Allowed requests still pass canonicalization (no traversal, no double encoding,
no absolute URLs, no control characters), still go to the pinned endpoint, and
still appear in the audit log — under rule `blocklist.unlisted`, so you can see
exactly what the mode admitted. Grep for it.

### Enabling it

```
--policy-mode blocklist --all-projects
```

The connector prints a startup warning, and the mode changes the policy hash the
gateway pins per connector — so a blocklist instance cannot quietly join a
connector whose other instances enforce the allowlist.

## Reverting

Both modes are reversible with a restart. Drop `--credential-mode` (restore
`--secret-file`, and set the integration back to `agent_local`, which requires
deleting and recreating it so the stored credential goes away), or drop
`--policy-mode`.
