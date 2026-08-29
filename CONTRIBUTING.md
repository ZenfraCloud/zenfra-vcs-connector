# Contributing

Thanks for looking. This is the customer-run half of Zenfra's private VCS
connectivity: it sits inside a customer network holding a VCS credential, so
changes are reviewed with that in mind — small, tested, and explicit about what
they widen.

**Security problems do not go in issues or pull requests.** See
[SECURITY.md](SECURITY.md).

## Getting set up

Go 1.26.3 or later is the only hard requirement:

```bash
go build ./...
go test -race ./...
```

Optional tools, needed for the packaging tests and linting:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.9.0
go install github.com/goreleaser/goreleaser/v2@latest
brew install helm            # or your platform's equivalent
```

The packaging tests skip when `goreleaser` or `helm` is missing, so a plain
`go test ./...` passes without them — CI runs with both installed.

## Before you open a pull request

```bash
go build ./...
go test -race ./...
golangci-lint run ./...
gosec -exclude-generated ./...
go test ./scripts/...        # reproducible build, goreleaser config, Helm chart
```

CI runs exactly these.

## Things the tests will not let you skip

Several checks fail the build rather than trusting review:

- **Every allowlist rule needs an allow test.** `TestEveryRuleIsCovered`
  (`internal/policy/policy_test.go`) fails if a rule in any vendor table has no
  test proving a real request matches it. Add the rule and its test together.
- **Every opt-in mode needs its trade-off written down.** `scripts/docs_test.go`
  fails if a mode is added without naming what it gives up in
  [`docs/optional-modes.md`](docs/optional-modes.md).
- **Packaging must stay honest.** `scripts/packaging_test.go` runs
  `goreleaser check`, `helm lint`, `helm template`, and proves the binary is
  byte-reproducible and that `scripts/verify-reproducible-build.sh` uses the same
  flags goreleaser does. Changing the chart or the release config means running
  these locally with both tools installed.

## House style

- Every file starts with two `// ABOUTME:` lines saying what it is.
- Comments explain *why*, especially where a security property depends on the
  shape of the code (canonicalize-once, no redirects, credential injection).
- Tests are named for the behaviour they pin, not the function they call.
- No new dependencies without a reason that survives "can the standard library
  do this?" — the module ships two direct dependencies on purpose, because
  customers audit it and reproducible builds get harder with every addition.

## Changes that need a conversation first

Open an issue before writing code if you want to:

- add or widen an allowlist rule, or add a vendor;
- add a listener, a flag that opens a port, or anything that changes what the
  connector can reach;
- change the tunnel wire protocol in `tunnel/` — the gateway on the other end
  ships separately and must be updated in lockstep.

## Releases

Maintainers tag `vX.Y.Z` on `main`; the release workflow builds reproducible
binaries and a multi-arch image, publishes `SHA256SUMS`, and signs both with
cosign keyless. There is nothing to do in a pull request for a release.
