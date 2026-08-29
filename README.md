# Zenfra VCS Connector

Outbound-only connector that lets Zenfra reach a private, firewalled VCS
(GitLab, GitHub Enterprise Server, Bitbucket Data Center, Azure DevOps Server)
without any inbound access to the customer network.

The connector dials **out** to the Zenfra gateway over WebSocket, receives
allowlisted VCS API requests, injects the upstream credential from a local
secret file and streams the response back. The credential never leaves the
customer's network and the allowlist is compiled into the binary per vendor.

## Install

### Container

```bash
docker run --rm \
  -e ZENFRA_VCS_CONNECTOR_GATEWAY_URL=https://api.zenfra.cloud \
  -e ZENFRA_VCS_CONNECTOR_BOOTSTRAP_TOKEN=vcsc_... \
  -e ZENFRA_VCS_CONNECTOR_ENDPOINT=https://gitlab.internal \
  -e ZENFRA_VCS_CONNECTOR_VENDOR=gitlab \
  -e ZENFRA_VCS_CONNECTOR_ALLOWED_PROJECTS=42 \
  -e ZENFRA_VCS_CONNECTOR_SECRET_FILE=/run/secrets/vcs-token \
  -v /path/to/token:/run/secrets/vcs-token:ro \
  ghcr.io/zenfracloud/zenfra-vcs-connector:latest
```

### Binary

Download the archive for your platform from the release, verify it against
`SHA256SUMS`, then run `zenfra-vcs-connector --help` for the full flag list.
Every flag has a `ZENFRA_VCS_CONNECTOR_*` environment equivalent.

### Kubernetes (Helm)

```bash
kubectl create secret generic zenfra-vcs-connector \
  --from-literal=bootstrap-token=vcsc_... \
  --from-literal=credential=glpat-...

helm install vcs-connector deploy/helm/zenfra-vcs-connector \
  --set connector.gatewayUrl=https://api.zenfra.cloud \
  --set connector.endpoint=https://gitlab.internal \
  --set 'connector.allowedProjects={42}' \
  --set secret.name=zenfra-vcs-connector
```

Behind a corporate proxy, set `proxy.httpsProxy` / `proxy.noProxy`; for an
internal CA, mount the PEM bundle with `caBundle.configMapName` plus
`caBundle.gatewayKey` and/or `caBundle.upstreamKey`.

## Documentation

| | |
|---|---|
| [Setup guide](docs/setup.md) | Create a connector, run an instance, bind an integration, troubleshoot |
| [Security model](docs/security.md) | Threat model and the properties this connector guarantees |
| [Optional modes](docs/optional-modes.md) | `control_plane` credentials and blocklist policy, and what each gives up |
| [Contributing](CONTRIBUTING.md) | Build, test, and the gates that fail the build |
| [Security policy](SECURITY.md) | Reporting a vulnerability |

## Building from source

```bash
go build ./...
go test -race ./...
```

Go 1.26.3 or later; no other tooling is required. The module has two direct
dependencies (`gorilla/websocket`, `google.golang.org/protobuf`) and does not
depend on anything else in Zenfra.

## Releases

Tagging `vX.Y.Z` builds static `linux/amd64` and `linux/arm64` binaries, a
multi-arch image and `SHA256SUMS`, all signed with cosign keyless.

Builds are reproducible: `scripts/verify-reproducible-build.sh` rebuilds the
same commit from a second source path and asserts the binaries are
byte-identical, so a third party can confirm a published binary matches this
source.

Verify a published release:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/ZenfraCloud/zenfra-vcs-connector/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle SHA256SUMS.cosign.bundle SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

## License

[Apache License 2.0](LICENSE).
