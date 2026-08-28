#!/usr/bin/env bash
# ABOUTME: Proves the connector binary is reproducible: same source, same bytes.
# ABOUTME: Builds twice from two different paths and compares the SHA-256 digests.
#
# A customer who does not trust our release pipeline can run this against a tag
# and compare the digest with the published SHA256SUMS. The build flags here
# MUST stay identical to .goreleaser.yaml's — that is the whole point.
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: verify-reproducible-build.sh [--version VERSION] [--goos GOOS]
                                    [--goarch GOARCH] [--expect SHA256]

Builds the connector twice from separate copies of this module and fails if the
two binaries differ. Prints the SHA-256 digest on success.

--version takes the released version with or without the leading "v"; the digest
is the same either way, because the binary is stamped with the goreleaser form
(no "v"). --expect additionally compares the digest with the one published in
SHA256SUMS, which is how a third party confirms a release matches this source.
USAGE
}

VERSION="dev"
BUILD_GOOS="linux"
BUILD_GOARCH="amd64"
EXPECTED=""

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --goos)    BUILD_GOOS="${2:?--goos needs a value}"; shift 2 ;;
        --goarch)  BUILD_GOARCH="${2:?--goarch needs a value}"; shift 2 ;;
        --expect)  EXPECTED="${2:?--expect needs a value}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# goreleaser stamps {{ .Version }}, which drops the tag's leading "v". Stamping
# anything else produces a different binary, so normalize before building.
VERSION="${VERSION#v}"

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The release builds with exactly the toolchain go.mod names; pin it here so a
# verifier's own Go version cannot change the digest.
BUILD_TOOLCHAIN="${BUILD_TOOLCHAIN:-go$(awk '/^go /{print $2; exit}' "$MODULE_DIR/go.mod")}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Two copies at different paths: -trimpath is what makes that irrelevant, so
# building from one path only would not prove anything.
build_at() {
    local name="$1" src="$WORK_DIR/$1"
    mkdir -p "$src"
    # git archive would drop uncommitted work; a plain copy verifies the tree
    # you actually have. dist/ is goreleaser output, never an input.
    tar -C "$MODULE_DIR" --exclude=./dist --exclude=./.git -cf - . | tar -C "$src" -xf -
    (
        cd "$src"
        # The go directive in go.mod is a floor, not a pin: without GOTOOLCHAIN a
        # customer on a newer Go builds different bytes and reads it as tampering.
        GOWORK=off CGO_ENABLED=0 GOOS="$BUILD_GOOS" GOARCH="$BUILD_GOARCH" \
            GOTOOLCHAIN="$BUILD_TOOLCHAIN" \
            go build -trimpath -buildvcs=false \
            -ldflags "-s -w -X main.version=${VERSION}" \
            -o "$WORK_DIR/$name.bin" ./cmd/zenfra-vcs-connector
    )
}

digest() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

echo "building ${BUILD_GOOS}/${BUILD_GOARCH} version=${VERSION} twice..."
build_at first
build_at second

FIRST="$(digest "$WORK_DIR/first.bin")"
SECOND="$(digest "$WORK_DIR/second.bin")"

if [ "$FIRST" != "$SECOND" ]; then
    echo "NOT REPRODUCIBLE: $FIRST != $SECOND" >&2
    exit 1
fi

if [ -n "$EXPECTED" ] && [ "$FIRST" != "$EXPECTED" ]; then
    echo "DIGEST MISMATCH: built $FIRST, expected $EXPECTED (toolchain $BUILD_TOOLCHAIN)" >&2
    exit 1
fi

echo "reproducible: $FIRST"
