# Security Policy

The VCS Connector runs inside a customer's network and holds a credential for
their version control system. Its security properties are the product. This
page says how to report a problem and what the connector guarantees.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately through GitHub's [Report a vulnerability][advisory] on this
repository, or email **security@zenfra.cloud**. Include the version
(`zenfra-vcs-connector --version`), the vendor and configuration involved, and
the smallest reproduction you have.

[advisory]: https://github.com/ZenfraCloud/zenfra-vcs-connector/security/advisories/new

What to expect:

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix or mitigation plan | agreed with you before disclosure |
| Credit | offered in the advisory unless you prefer otherwise |

Please give us a reasonable window to ship a fix before disclosing publicly.

## Supported versions

Until 1.0, the latest minor release receives security fixes. After 1.0 the
current and previous minor releases will be supported.

## What the connector guarantees

These are the properties a report can hold us to. The full threat model is in
[`docs/security.md`](docs/security.md).

- **The upstream credential stays in your network.** It is read from a file you
  mount and injected into the upstream request inside the connector. It is never
  sent to Zenfra, never written to the connector's own logs, and never appears in
  its audit records. (The opt-in `--credential-mode control_plane` deliberately
  reverses this for GitLab only; see [`docs/optional-modes.md`](docs/optional-modes.md).)
- **Outbound-only.** The connector opens a WebSocket to the Zenfra gateway. It
  listens on no port unless you enable the metrics endpoint or the webhook
  receiver, and it needs no inbound firewall rule.
- **Default-deny allowlist.** Only the vendor API paths compiled into the binary
  can be requested, matched after a single canonicalization pass, with the exact
  bytes that were matched sent upstream. Requests outside `--allowed-projects`
  are refused locally.
- **No redirect following.** The HTTP client never follows redirects. One
  vendor rule (GitHub Enterprise codeload) may follow exactly one, and only to an
  operator-configured origin, without the credential.
- **Header allowlists both directions.** Credential headers arriving from the
  control plane are refused, not stripped; response headers are filtered to a
  fixed list that contains no `Set-Cookie` or `WWW-Authenticate`.
- **Revocable.** Every instance holds its own enrollment key. Revoking one from
  Zenfra closes its streams immediately and it can never register again, not even
  with a valid bootstrap token.
- **Reproducible builds.** Release binaries are byte-reproducible from source;
  `scripts/verify-reproducible-build.sh --expect <sha256>` checks a published
  artifact. Checksums and the container image are signed with cosign (keyless).

## Out of scope

- The Zenfra control plane and gateway (report those to security@zenfra.cloud too,
  but they are not this repository).
- Vulnerabilities in the customer's own VCS.
- Findings that require an attacker who already has the connector's credential
  file or root on its host.
- Denial of service through configuration you control (connection counts, size
  caps, timeouts).
