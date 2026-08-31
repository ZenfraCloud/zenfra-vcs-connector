# VCS Connector Setup

Connect Zenfra to a self-hosted VCS that has no inbound path from the internet —
GitLab, GitHub Enterprise Server, Bitbucket Data Center or Azure DevOps Server.

You run the **VCS Connector** inside your network. It dials out to Zenfra and holds
that connection open; Zenfra never connects in. No firewall rules, no VPN, no public
endpoint. Why it is safe to run is [VCS Connector — Security Model](security.md).

Budget 15 minutes. Four steps: create the connector, run it, bind an integration,
use a repository.

## Before you start

- **Egress** from wherever the connector runs to `https://api.zenfra.cloud` on 443.
  An authenticated corporate proxy is fine — see [Behind a proxy](#behind-a-proxy).
- **Network reach** from the connector to your VCS.
- **A VCS personal access token** with the scopes Zenfra needs (`read_api` plus
  `read_repository` for GitLab; equivalent read scopes elsewhere). It stays on the
  connector's disk — Zenfra never receives it.
- **A Zenfra JWT** for an org admin, for the API calls below.
- **Docker, a Linux host, or a Kubernetes cluster** for the connector itself. It idles
  under 50 MiB RSS.

## Step 1 — Create the connector

One connector per VCS endpoint. `vendor` is `gitlab`, `github`, `bitbucket` or
`azure_devops`; `endpoint` is the base URL of your VCS (for Azure DevOps Server,
include the collection).

```bash
curl -X POST "https://api.zenfra.cloud/api/v1/vcs/connectors" \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "gitlab-internal",
    "vendor": "gitlab",
    "endpoint": "https://gitlab.internal"
  }'
```

```json
{
  "connector": {
    "id": "507f1f77bcf86cd799439011",
    "name": "gitlab-internal",
    "vendor": "gitlab",
    "endpoint": "https://gitlab.internal",
    "created_at": "2026-08-28T10:30:00Z"
  },
  "bootstrap_token": "vcsc_XXXXXXXXXXXX.YYYYYYYYYYYYYYYYYYYYYYYY"
}
```

> **The `bootstrap_token` is returned exactly once.** It is served `no-store`, stored
> hashed, kept out of audit records, and cannot be retrieved later. Put it in your
> secret manager now. If you lose it, `POST /api/v1/vcs/connectors/<id>/rotate-key`
> issues a new one and leaves the old working for a one-hour grace window.

## Step 2 — Run a connector instance

Pick one of the three. All three need the same six things: where Zenfra is, the
bootstrap token, your VCS endpoint and vendor, the file holding your VCS token, and
which projects this connector may serve.

`--allowed-projects` is **required** unless you pass `--all-projects` — there is no
implicit default. A request for a project outside the list is denied even if the
operation itself is allowlisted.

Write each entry in the form the vendor's own API URLs use, because that is what
the connector matches against:

| Vendor | Entry form | Example |
|---|---|---|
| GitLab | the **numeric project ID** — Zenfra addresses GitLab projects by ID, not by path | `42,1337` |
| GitHub Enterprise | `owner/repo` | `acme/infra` |
| Bitbucket Data Center | `PROJECTKEY/repo-slug` | `INFRA/terraform` |
| Azure DevOps Server | `project/repo` | `Platform/infra` |

Getting this wrong is quiet: verify and repository discovery are project-independent,
so the connector still reports `healthy` and the denial only appears the first time a
stack tries to read from a repository.

Every flag has a `ZENFRA_VCS_CONNECTOR_*` environment equivalent (flags win).
Run `zenfra-vcs-connector --help` for the full list.

### Container

Create the secret files **before** `docker run` — if the mount source does not
exist, Docker silently creates it as a directory and the connector fails with
"secret file is a directory".

```bash
sudo mkdir -p /etc/zenfra /var/lib/zenfra-connector
printf '%s' 'glpat-XXXXXXXXXXXX' | sudo tee /etc/zenfra/vcs-token >/dev/null
# 0644, not 0400: the image runs as UID 65532 (distroless nonroot), so a
# root-owned 0400 file is unreadable inside the container. Alternatively
# `chown 65532` and keep it 0600.
sudo chmod 0644 /etc/zenfra/vcs-token
sudo chown 65532:65532 /var/lib/zenfra-connector

docker run -d --restart=unless-stopped --name zenfra-vcs-connector \
  -e ZENFRA_VCS_CONNECTOR_GATEWAY_URL=https://api.zenfra.cloud \
  -e ZENFRA_VCS_CONNECTOR_BOOTSTRAP_TOKEN=vcsc_... \
  -e ZENFRA_VCS_CONNECTOR_ENDPOINT=https://gitlab.internal \
  -e ZENFRA_VCS_CONNECTOR_VENDOR=gitlab \
  -e ZENFRA_VCS_CONNECTOR_ALLOWED_PROJECTS=42,1337 \
  -e ZENFRA_VCS_CONNECTOR_SECRET_FILE=/run/secrets/vcs-token \
  -e ZENFRA_VCS_CONNECTOR_ENROLLMENT_KEY_FILE=/state/enrollment-key \
  -e ZENFRA_VCS_CONNECTOR_INSTANCE_KEY="$(hostname)" \
  -v /etc/zenfra/vcs-token:/run/secrets/vcs-token:ro \
  -v /var/lib/zenfra-connector:/state \
  ghcr.io/zenfracloud/zenfra-vcs-connector:latest
```

The state volume and `ENROLLMENT_KEY_FILE` persist this instance's own
enrollment key, so restarts re-authenticate as the same instance instead of
re-registering with the fleet-wide bootstrap token — without it, per-instance
revocation cannot do its job. `INSTANCE_KEY` pins a stable identity; left
unset it defaults to the container ID, which changes on every recreate and
piles up instance records until the 30-day reclaim.

No `-p` and no docker socket: the connector needs neither. That is the "no inbound
path" property, enforced by your `docker run` line rather than promised by us.

### Binary

Download the archive for your platform, verify it, run it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
tar xzf zenfra-vcs-connector_<version>_linux_amd64.tar.gz

./zenfra-vcs-connector \
  --gateway-url https://api.zenfra.cloud \
  --bootstrap-token "$(cat /etc/zenfra/bootstrap-token)" \
  --endpoint https://gitlab.internal \
  --vendor gitlab \
  --allowed-projects 42,1337 \
  --secret-file /etc/zenfra/vcs-token
```

Builds are reproducible — `scripts/verify-reproducible-build.sh --expect <sha256>`
rebuilds the tagged commit and asserts a byte-identical binary, so you can confirm
the artifact matches the public source.

For a systemd unit, run it as a non-root user, `Restart=on-failure`, and note the
exit codes: **2** means fix your configuration (never retry), **1** means a runtime
failure (retrying is reasonable).

### Kubernetes (Helm)

The chart never templates secret material — you create the Secret, the chart mounts
it. Your credential stays out of `values.yaml`, git history and `helm get values`.

```bash
kubectl create secret generic zenfra-vcs-connector \
  --from-literal=bootstrap-token=vcsc_... \
  --from-literal=credential=glpat-...

helm install vcs-connector vcs-connector/deploy/helm/zenfra-vcs-connector \
  --set connector.gatewayUrl=https://api.zenfra.cloud \
  --set connector.endpoint=https://gitlab.internal \
  --set connector.vendor=gitlab \
  --set 'connector.allowedProjects={42,1337}' \
  --set secret.name=zenfra-vcs-connector
```

`replicaCount` defaults to 2 — instances are independent and active-active, so a
rolling upgrade never drops the tunnel entirely.

### Confirm it connected

```bash
curl -s "https://api.zenfra.cloud/api/v1/vcs/connectors/<connector-id>" \
  -H "Authorization: Bearer <your-jwt>" | jq .health
```

```json
{
  "status": "healthy",
  "active_streams": 4,
  "interactive_streams": 3,
  "bulk_streams": 1,
  "instances": 1
}
```

`healthy` means both lanes are live: the interactive lane for API calls, the bulk
lane for archive downloads. Anything else, see [Troubleshooting](#troubleshooting).

## Step 3 — Bind a VCS integration to the connector

Same integration object as a public VCS, with `transport: connector`. There is no
`base_url` and no token in this request — the endpoint comes from the connector
record, and the credential stays on the connector.

```bash
curl -X POST "https://api.zenfra.cloud/api/v1/vcs/integrations" \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "gitlab",
    "transport": "connector",
    "vcs_connector_id": "507f1f77bcf86cd799439011",
    "credential_mode": "agent_local",
    "display_name": "Internal GitLab"
  }'
```

The integration is created **pending**. Verify it — this makes a tunneled
"who am I" call and records the identity your connector's own credential
authenticates as:

```bash
curl -X POST ".../api/v1/vcs/integrations/<integration-id>/verify" -H "Authorization: Bearer <your-jwt>"
curl -X POST ".../api/v1/vcs/integrations/<integration-id>/repos/sync" -H "Authorization: Bearer <your-jwt>"
curl -s     ".../api/v1/vcs/integrations/<integration-id>/repos"      -H "Authorization: Bearer <your-jwt>"
```

Bitbucket Data Center and Azure DevOps Server are **connector-only** — they have no
public-endpoint form in Zenfra.

## Step 4 — Use a repository

Point a stack at a synced repository exactly as you would for a public VCS. When a
run starts, Zenfra fetches the source archive through the connector's bulk lane and
serves it to the worker over the same one-time `source_url` as any other run — the
worker needs no connector configuration and no network path to your VCS.

## Optional extras

### Behind a proxy

Standard Go proxy variables, honoured on every leg. Only these explicit variables
are supported — PAC/WPAD auto-configuration and Kerberos/NTLM proxy authentication
are not, so use an explicit proxy URL with basic auth (or allow `api.zenfra.cloud`
through unauthenticated). Keep your internal VCS off the proxy with `NO_PROXY`:

```bash
-e HTTPS_PROXY=http://user:pass@proxy.internal:3128
-e NO_PROXY=gitlab.internal
```

Helm: `proxy.httpsProxy`, `proxy.httpProxy`, `proxy.noProxy`.

### Private CA

Two separate bundles, because the two legs have genuinely different trust: Zenfra is
publicly signed, your VCS usually is not.

```
--ca-bundle           /etc/ssl/certs/corporate-root.pem   # Zenfra leg
--upstream-ca-bundle  /etc/ssl/certs/internal-ca.pem      # VCS leg
```

Helm: `caBundle.configMapName` plus `caBundle.gatewayKey` / `caBundle.upstreamKey`.
An unreadable bundle fails at startup, not per request.

### Durable per-instance revocation

```
--enrollment-key-file /var/lib/zenfra-vcs-connector/instance.key
```

The instance uses the bootstrap token exactly once, then persists a per-instance key
(0600, atomic replace). After that, revoking the instance holds even against someone
who stole the fleet-wide bootstrap token, and the connector never falls back. Mount a
writable volume for it; without the flag, each restart re-registers with the
bootstrap token.

Helm: on by default via `connector.enrollmentKeyDir` (`/var/lib/zenfra-vcs-connector`),
backed by a per-pod `emptyDir` — the only writable path in an otherwise read-only root
filesystem. The key survives container restarts; a rescheduled pod gets a new name and
therefore a new instance record, so it re-bootstraps by design. **Never point two
replicas at the same volume**: both would resolve to one instance record and each
refresh would evict the other's streams. Set it to `""` to bootstrap on every restart.

One connector holds at most **200 live instance records**. Records for instances that
stop reporting are reclaimed automatically 30 days after their last contact, so a
Deployment that churns pod names is fine at normal rollout rates (a host that comes
back after that long re-enrols with its bootstrap token by itself) — but a connector
that hits the cap refuses new registrations until you prune. List with
`GET /api/v1/vcs/connectors/<id>/instances` and revoke the ones no longer running with
`DELETE /api/v1/vcs/connectors/<id>/instances/<instance-id>`.

### Metrics

```
--metrics-addr 0.0.0.0:9090
```

Off by default — opening a listener inside your network is your call. Prometheus text
format, stdlib-only (no client library dependency):
`zenfra_vcs_connector_tunnel_streams`, `..._stream_connects_total`,
`..._requests_total`, `..._request_errors_total`, `..._request_duration_seconds`,
`..._start_time_seconds`. Helm: `metrics.enabled`, `metrics.port`.

### Push triggers

```
--webhook-addr 0.0.0.0:8080 --webhook-secret-file /etc/zenfra/webhook-secret
```

Both flags are required together — an unauthenticated listener inside your network
would let anything on it trigger runs. Point your VCS's webhook at
`http://<connector-host>:8080/webhook`; it verifies the secret locally and relays
only verified deliveries over the tunnel. Deliveries larger than 64 KiB are refused
with `413`.

Not available through the Helm chart yet: it templates neither the webhook flags nor
a Service for the listener. Run the connector as a container or a binary to use push
triggers.
Answers are `202` accepted, `401` refused, `503` redeliver, `204` refused by Zenfra.

### Opt-in modes

`--credential-mode control_plane` and `--policy-mode blocklist` each give up a
property the connector otherwise guarantees. Both are off by default and documented
with their costs in
[`docs/optional-modes.md`](optional-modes.md).

## Troubleshooting

### Health status meanings

| Status | Meaning | Do |
|---|---|---|
| `healthy` | Both lanes live | — |
| `degraded` | One lane live, the other not. Interactive-only: browsing works, archive downloads (and therefore runs) do not | Check connector logs for a failing dial; the bulk lane is a separate connection and can fail alone |
| `offline` | Zero live streams | See [The connector will not connect](#the-connector-will-not-connect) |
| `policy_mismatch` | An instance is reaching the gateway but its vendor / endpoint / policy fingerprint is not the one pinned on this connector | See [policy_mismatch](#policy_mismatch) |
| `unknown` | No gateway registry wired (Zenfra-side misconfiguration) | Contact support |

Health is read-only: you can bind an integration, rotate the key or revoke instances
while the connector is offline. There is no rename — name, vendor and endpoint are
fixed at creation. Reconfiguring is usually how you bring one back.

### The connector exits immediately with code 2

Configuration is wrong and no amount of retrying fixes it. The message names both the
flag and the environment variable. Common causes: `--allowed-projects` missing without
`--all-projects`; `--secret-file` set in `control_plane` credential mode (or missing in
the default mode); an unparseable `--metrics-addr`; an unreadable CA bundle;
`--policy-mode blocklist` without `--all-projects`.

### The connector will not connect

Read its stderr first — it says what it is doing.

| Symptom | Cause | Fix |
|---|---|---|
| `401` on register, then exit | Bootstrap token wrong, or rotated out past its grace window | Rotate the key and redeploy with the new token |
| `401 instance_unknown`, then `re-enrolling with the bootstrap token` | The host was offline longer than the 30-day record TTL, so its enrollment key names a reclaimed instance | None — the connector re-enrols with the bootstrap token it still has. If the token was removed after enrolment, the connector exits 2 instead: start it once with the token again |
| `403 instance_revoked` | This instance was revoked | Revocation is permanent for that `--instance-key`: delete the enrollment key file and start the connector under a new instance key |
| `401 token_superseded`, then reconnects | A peer stream refreshed the token every stream shares | None — the stream re-mints and reconnects on its own |
| `403` on the tunnel upgrade | Fingerprint mismatch — see below | |
| Reconnect loop, no HTTP status | No egress to `api.zenfra.cloud`, or a proxy is not configured | Check `HTTPS_PROXY`; confirm 443 egress |
| TLS error dialing the gateway | Your egress appliance re-signs TLS and its root is not trusted | Set `--ca-bundle` to your corporate root |
| Connected, then drops every few seconds | An idle-timeout on a proxy below Zenfra's 30 s keepalive | Raise the proxy's `read_timeout` above 30 s |

Reconnects are automatic with jittered backoff from 1 s to a 30 s cap, indefinitely.
A connection that has been up for 45 minutes is closed on purpose so reconnecting
reauthenticates — that is not a fault.

### `policy_mismatch`

An instance announced a vendor, endpoint or allowlist fingerprint that is not the one
pinned on the connector by its first-ever instance. Almost always one of:

- The connector was upgraded to a version with a different allowlist. The fingerprint
  is pinned by the first instance ever admitted and there is no API to re-pin it, so
  rolling *forward* does not clear the mismatch — either roll back to the version
  that set the pin, or delete the connector and create a new one (new bootstrap
  token, rebind the integration, re-sync repositories). Release notes call out any
  version that changes the allowlist.
- `--endpoint` differs (trailing slash, `http` vs `https`, a different host). It is
  canonicalized, but a genuinely different host is a genuinely different connector.
- `--vendor` differs.
- One instance runs `--policy-mode blocklist` and the others do not. Blocklist mode
  changes the fingerprint deliberately, so it cannot quietly join an allowlist fleet.

A mismatched instance is refused **before** the connection is upgraded, so it never
becomes a stream — which is why the state is reported separately rather than looking
like plain `offline`.

### A VCS call fails

Zenfra surfaces a typed code. The ones you can act on:

| Code | Meaning |
|---|---|
| `connector_offline` | No live stream for this connector. Runs surface this as **422** naming the connector, rather than a retried 5xx |
| `policy_denied` | The connector refused it. Grep its log for `"decision":"deny"` — the record names the rule and the reason (unallowlisted path, wrong method, or a project outside `--allowed-projects`) |
| `connector_busy` | Every stream is in use. Raise `--interactive-connections` or add an instance |
| `upstream_dns` / `upstream_conn` / `upstream_tls` / `upstream_timeout` | The connector could not reach your VCS. This is the connector→VCS leg: DNS, routing, `--upstream-ca-bundle` |
| `upstream_http` | Your VCS answered with an error. Usually the PAT's scopes or a project the token cannot see |
| `too_large` | Request body over 1 MiB, interactive response over 16 MiB, or a repository archive over 100 MiB on the bulk lane |
| `outcome_unknown` | The stream died after the request was dispatched. Zenfra deliberately does **not** retry — a replay could double a side effect. Check your VCS to see whether it landed |
| `stream_lost_before_dispatch` | The stream died before sending. Safe methods are retried once automatically |

### Finding a request in your own logs

Every exchange is one JSON line on the connector's **stderr**, allowed or denied:

```bash
docker logs zenfra-vcs-connector | jq 'select(.decision == "deny")'
docker logs zenfra-vcs-connector | jq 'select(.request_id == "<id>")'
```

Fields: `request_id`, `decision`, `method`, `path`, `lane`, `elapsed_ms`, and where
they apply `rule`, `purpose`, `project`, `status`, `error`, `reason`,
`request_bytes`, `response_bytes`. No field can hold a credential, at any log level.

### Rotating things

| Rotate | How | Downtime |
|---|---|---|
| The VCS token | Overwrite the secret file (atomic replace) | None — it is re-read per request |
| The bootstrap token | `POST /api/v1/vcs/connectors/<id>/rotate-key`, then redeploy instances | None — the old token works for one hour |
| An instance's access | `DELETE /api/v1/vcs/connectors/<id>/instances/<instance-id>` | That instance only; its streams close immediately |
| The whole connector | `DELETE /api/v1/vcs/connectors/<id>` | Drains and closes every stream; reconnects refused |

If the bootstrap token **leaked**, rotating it is only half the job: anything that
already registered with it holds its own enrollment key and keeps working. After
rotating, list the instances (`GET /api/v1/vcs/connectors/<id>/instances`) and revoke
every one you do not recognise — a revoked instance can never re-register, not even
with a valid bootstrap token.

## Reference

- API: `POST|GET /api/v1/vcs/connectors`, `GET|DELETE /api/v1/vcs/connectors/:id`,
  `POST /api/v1/vcs/connectors/:id/rotate-key`,
  `GET /api/v1/vcs/connectors/:id/instances`,
  `DELETE /api/v1/vcs/connectors/:id/instances/:instanceId`
- Security model: [security.md](security.md)
- Connector source and optional modes: [README](../README.md),
  [optional-modes.md](optional-modes.md)
- Reporting a vulnerability: [SECURITY.md](../SECURITY.md)
