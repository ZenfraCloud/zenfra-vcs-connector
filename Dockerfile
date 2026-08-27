# ABOUTME: Multi-stage Dockerfile for the customer-run Zenfra VCS Connector.
# ABOUTME: Static binary on a minimal base; the connector needs no shell, git or docker.

FROM --platform=$BUILDPLATFORM mirror.gcr.io/library/golang:1.26.3-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /build
# The module has no dependency on the rest of the monorepo, so the build context
# is just this directory — the connector ships from its own public repo.
COPY . ./

# GOWORK=off: the image build must not depend on the monorepo go.work.
ENV GOWORK=off
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -mod=mod \
        -ldflags="-w -s -X main.version=${VERSION}" \
        -o zenfra-vcs-connector \
        ./cmd/zenfra-vcs-connector

FROM mirror.gcr.io/library/alpine:3.22
RUN apk add --no-cache ca-certificates && \
    addgroup -g 1000 connector && \
    adduser -D -u 1000 -G connector connector
COPY --from=builder /build/zenfra-vcs-connector /usr/local/bin/zenfra-vcs-connector
USER connector:connector
ENTRYPOINT ["/usr/local/bin/zenfra-vcs-connector"]
