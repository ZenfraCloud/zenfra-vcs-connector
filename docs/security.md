# VCS Connector — Security Model

This page describes what the VCS Connector can and cannot do, and why. It is the
document to hand to whoever has to approve running a Zenfra component inside your
network.

Setup instructions live in [VCS Connector Setup](setup.md).

## The one-paragraph version

You run an open-source binary inside your network. It dials **out** to Zenfra over
TLS and holds that connection open; Zenfra never connects in. Over that connection
Zenfra can ask it to perform a bounded set of VCS API calls — the list is compiled
into the binary you can read — scoped to the projects you name. The connector adds
your VCS token to those calls from a file on your disk, so the token never leaves
your network. Every request it serves, allowed or denied, is one line in your own
logs.

## Threat model

Three actors, and what each one can do:

| If this is compromised | It can | It cannot |
|---|---|---|
| **Zenfra's control plane** | Ask your connector to perform any operation on the compiled allowlist, for the projects you scoped it to | Obtain your VCS credential; reach any host other than the endpoint you pinned; reach any path off the allowlist; open a connection into your network |
| **The connector process** | Do what it was already authorized to do — it holds your credential and network position | Be reached from outside your network (it has no listener unless you enable one); be pointed at a different upstream (the endpoint is fixed at startup) |
| **A holder of your bootstrap token** | Enroll a new connector instance against your Zenfra connector | Change the pinned vendor/endpoint/policy; serve another organization; keep access after you revoke that instance (with per-instance enrollment keys enabled) |

The design assumption is deliberately unflattering to us: **a fully compromised
Zenfra should not yield your VCS credential or unbounded access to your VCS.**

## Property 1 — the token stays home

In the default `agent_local` credential mode:

- The upstream credential is a file on the connector's disk (`--secret-file`).
  Zenfra never sees it, never stores it and cannot ask for it.
- The connector reads that file **after** the request passes policy, on every
  request. Rotating the file takes effect on the next request with no restart.
- A credential arriving *from* Zenfra over the tunnel is **refused** with a
  `protocol` error, not quietly stripped. The control plane holds no credential for
  your upstream, so one showing up is a bug or an attack — and stripping it would
  launder the request into a valid call.
- Binding an integration to a connector stores **no** token control-plane-side. The
  integration is verified by making a tunneled "who am I" call and observing which
  identity your connector's own credential authenticates as.

The connector formats the token per vendor: `PRIVATE-TOKEN` for GitLab,
`Authorization: Bearer` for GitHub Enterprise and Bitbucket Data Center,
`Authorization: Basic` (empty username) for Azure DevOps Server. You store the raw
PAT; the connector does the encoding.

An opt-in `control_plane` credential mode exists and gives this property up on
purpose. It is off by default, must be enabled on both sides, and its costs are
written out in
[`docs/optional-modes.md`](optional-modes.md).

## Property 2 — the allowlist is auditable, and it is the default

The connector ships a compiled-in table of `(method, path pattern, purpose)` per
vendor. Anything that does not match is denied before the VCS is contacted. The
table is source you can read in the open-source repository — that is the point of
open-sourcing the connector.

Two more constraints sit on top of it:

- **`--allowed-projects`** — a request whose captured project is not in your list is
  denied even if the operation is allowlisted. Passing `--all-projects` instead is an
  explicit choice; one of the two is required, there is no default.
- **Canonicalize once, then match what you send.** The path is validated before
  matching and the *validated bytes* are what goes upstream. Encoded traversal,
  double encoding, backslashes, absolute URLs, userinfo, fragments, empty segments
  and control characters are all rejected pre-match. Percent escapes are decoded for
  validation only — decoding them for real would invent path segments and change what
  the request means. The rejection table is fuzz-tested, not just unit-tested.

An opt-in blocklist mode exists for operators who want it and is documented with the
guarantee it drops, in the same optional-modes page.

## Property 3 — outbound only

- The connector opens ~3 interactive connections plus 1 bulk connection (for archive
  downloads) to Zenfra. Zenfra sends requests down connections the connector already
  opened. There is no inbound path and no port to open.
- The connector binds **no listener at all** by default. `--metrics-addr` and
  `--webhook-addr` are both off unless you set them; whether anything listens inside
  your network is your decision.
- Standard `HTTPS_PROXY` / `NO_PROXY` are honoured on every leg, so an authenticated
  corporate egress proxy works with no connector-specific configuration.

## Property 4 — the request cannot be retargeted

The upstream host is fixed by `--endpoint` at startup. The tunnel carries a **path
and query only** — there is no field in the protocol that could name a host. So no
wire input, from a compromised control plane or anything on the path, can move a
request to a different host.

Redirects are not followed. The single exception is GitHub Enterprise's archive
download, which redirects to a codeload origin: that origin is pinned separately by
`--codeload-endpoint` (defaulting to the endpoint), and the redirected request is
re-evaluated against the allowlist before it is sent. A `Location` naming any other
host moves nothing.

## Property 5 — identity, rotation and revocation

- Connector creation returns a one-time **bootstrap token** (`vcsc_<key-id>.<secret>`),
  served with `Cache-Control: no-store`, hashed at rest, and never retrievable again.
  It is absent from audit payloads.
- An instance registers with that token and receives a short-lived (2 h)
  `typ=vcs_connector` JWT carrying its connector, instance and JTI. Connections are
  capped at 45 minutes so reconnecting always reauthenticates, and the token refreshes
  in-band before it can expire mid-connection.
- **Rotation** (`POST .../rotate-key`) issues a new bootstrap token and leaves the old
  one working for a one-hour grace window, so you can roll instances without an outage.
- **Revocation** is synchronous: revoking an instance or deleting a connector closes
  its live streams immediately and refuses the reconnect — the tunnel upgrade re-reads
  the instance record rather than trusting the JWT alone.
- With `--enrollment-key-file` set, an instance persists a **per-instance key** issued
  at first registration and stops using the bootstrap token. Revoking that instance
  then holds even against someone who stole the fleet-wide bootstrap token, and the
  connector never falls back to the bootstrap token when its own key is refused.

## Property 6 — the fingerprint is pinned

Each instance announces its vendor, canonical endpoint and **policy hash** (a digest
of the compiled allowlist table) when it dials in. The first instance ever admitted
pins that fingerprint on the connector record; afterwards a mismatch is refused with
a plain 403 *before* the connection is upgraded. A connector built with a different
allowlist — or aimed at a different endpoint — cannot quietly join a fleet, and the
connector's health reads `policy_mismatch` so you can see why.

## Property 7 — you get the audit trail too

The connector writes one structured JSON line per request to **stderr** (container
log collectors capture it identically; it leaves stdout free for anything you pipe):

```json
{"time":"...","level":"INFO","msg":"vcs request","request_id":"...",
 "decision":"allow","method":"GET","path":"/api/v4/projects/acme%2Finfra",
 "lane":"interactive","elapsed_ms":41,"rule":"gitlab.project.get",
 "purpose":"Get Project","project":"acme/infra","status":200,"response_bytes":1873}
```

The record type has **no field capable of holding a credential** — that is a property
of the type, not a habit of the caller, and it is asserted at debug level against the
upstream token, an upstream `Set-Cookie`, a secret in a response body and an inbound
bearer token.

Zenfra-side, the same requests are counted with bounded label cardinality
(`zenfra_vcs_tunnel_requests_total{lane,code}` and friends — never a connector, org,
path or token label), and connector lifecycle actions land in the organization audit
log as `vcs.connector.created` / `.key_rotated` / `.deleted`.

## What crosses the boundary

| Direction | Carries |
|---|---|
| Connector → Zenfra (on connect) | instance key, vendor, endpoint, policy hash, connector JWT |
| Zenfra → connector (per request) | method, path, query, an allowlisted header subset, deadline class, and a request body for the few write operations |
| Connector → Zenfra (per request) | status, an allowlisted response-header subset, response body in 32–64 KiB chunks |
| Connector → Zenfra (opt-in) | verified webhook deliveries, when `--webhook-addr` is enabled |

Response headers ride a narrow allowlist, so an upstream `Set-Cookie` can never
carry a VCS session into the control plane. Request bodies are capped at 1 MiB and
interactive responses at 16 MiB; archives stream through a 32 KiB buffer, so a
100 MiB archive costs the connector O(chunk) memory rather than 100 MiB.

## Verifying the binary you run

Releases publish `SHA256SUMS` plus a cosign signature bundle, and builds are
reproducible: `scripts/verify-reproducible-build.sh --expect <sha256>` rebuilds the
tagged commit and asserts the result is byte-identical to what we published. You do
not have to take our word for what the binary contains — you can rebuild it.

## Accepted limitations

- **The tunnel is a hard prerequisite.** With no live connector, connector-backed VCS
  calls fail; runs sourced from that VCS cannot start. The error names the connector
  rather than degrading to a generic 5xx.
- **Archives make a WAN round trip** (your VCS → connector → Zenfra → worker). Direct
  worker clone is a possible future optimization, not a shipped one.
- **The gateway rides `zenfra-api`'s deploy cadence.** A control-plane deploy drops
  tunnels; instances reconnect within the 30 s backoff cap.
