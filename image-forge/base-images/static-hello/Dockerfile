# syntax=docker/dockerfile:1.7
# =============================================================================
# Curated minimal/hardened base image — SAMPLE ("static-hello")
# =============================================================================
# This is the "base image we maintain" for the first slice of the hardened
# base-image supply chain. It is deliberately tiny but demonstrates the real
# hardening properties we want every curated image to have:
#
#   1. Multi-stage build — build tooling never reaches the final image.
#   2. Distroless-style final layer — no shell, no package manager, no libc
#      beyond what the binary needs. Pinned by DIGEST, not a floating tag,
#      so the build input is reproducible (matters for SLSA provenance).
#   3. Static binary — no dynamic linker, no OS package surface to patch.
#   4. Non-root runtime user.
#   5. OCI labels carrying source + purpose metadata (feeds provenance).
#
# The payload is intentionally trivial (a tiny static "hello" HTTP server)
# so the whole build -> scan -> SBOM -> sign/attest -> push -> verify pipeline
# can be proven end-to-end quickly. Swap the payload later; the hardening
# shape stays identical.
# =============================================================================

# --- Stage 1: build a fully static binary --------------------------------
# Pin golang by digest. The digest below is a PLACEHOLDER — resolve the real
# one on the build host before first use, e.g.:
#   docker buildx imagetools inspect golang:1.23-alpine
# then replace @sha256:... Keeping it pinned (not `golang:1.23-alpine`) is a
# supply-chain requirement, so this is intentionally not a floating tag.
FROM golang:1.23-alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS build

WORKDIR /src

# Build a static, position-independent binary with no cgo so the final image
# needs no libc / dynamic linker.
ENV CGO_ENABLED=0 \
    GOOS=linux

COPY server.go .

RUN go build \
      -trimpath \
      -ldflags="-s -w -buildid=" \
      -o /out/static-hello \
      ./server.go

# --- Stage 2: distroless-style final image -------------------------------
# gcr.io/distroless/static carries no shell and no package manager — minimal
# attack surface. Pin by DIGEST (placeholder below — resolve before use):
#   docker buildx imagetools inspect gcr.io/distroless/static:nonroot
# `nonroot` variant runs as uid 65532 by default.
FROM gcr.io/distroless/static:nonroot@sha256:1111111111111111111111111111111111111111111111111111111111111111

# OCI image labels — provenance-friendly metadata. source/revision are build
# args so CI can stamp the exact commit without editing the Dockerfile.
ARG SOURCE_REPO="https://github.com/arshiya19/Agentic_VOP"
ARG SOURCE_REVISION="dev"
LABEL org.opencontainers.image.title="sisyfix-static-hello" \
      org.opencontainers.image.description="Curated minimal/hardened sample base image (distroless, static, non-root)" \
      org.opencontainers.image.vendor="Sisyfix" \
      org.opencontainers.image.source="${SOURCE_REPO}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/static-hello /usr/local/bin/static-hello

# Already non-root via the `nonroot` base, but set it explicitly so the
# property survives a base change.
USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/static-hello"]
