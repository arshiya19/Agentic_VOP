# static-hello — curated minimal/hardened sample base image

This is the **base image we maintain** for the first slice of the hardened
base-image supply chain. It is deliberately tiny so the full pipeline
(build → scan → SBOM → sign/attest → push → verify) can be proven end to end,
while still demonstrating the hardening properties every curated image must have.

## What makes it hardened

| Property | How |
|----------|-----|
| No build tooling in the final image | Multi-stage build; the Go toolchain stays in stage 1 |
| No shell / no package manager | Final stage is `gcr.io/distroless/static` |
| No libc / dynamic linker to patch | Fully static binary (`CGO_ENABLED=0`) |
| Non-root runtime | `distroless:nonroot` + explicit `USER 65532:65532` |
| Reproducible build input | Base images pinned **by digest**, not floating tags |
| Provenance-friendly metadata | OCI labels (`source`, `revision`, `vendor`, …) |
| Smaller/stable binary | `-trimpath`, `-ldflags="-s -w -buildid="` |

## Before first build: resolve the pinned digests

The Dockerfile pins both base images by digest, but the two `@sha256:...`
values are **placeholders** (all-zeros / all-ones). Real digests must be
resolved on the build host — they are not committed as guesses, because an
incorrect digest is worse than none.

On the build box (which has `docker buildx`):

```sh
# Resolve the current digest for each base, for linux/arm64:
docker buildx imagetools inspect golang:1.23-alpine
docker buildx imagetools inspect gcr.io/distroless/static:nonroot
```

Copy the `linux/arm64` digest for each and replace the placeholder `@sha256:...`
values in the `Dockerfile` (stage 1 `golang`, stage 2 `distroless/static`).

> Note on architecture: the build box is ARM64 (Graviton / `t4g`). Pin the
> ARM64 digest. If you later build multi-arch, pin per-platform or pin the
> multi-arch index digest and let buildx select.

## Build (manual, on the build box)

```sh
cd image-forge/base-images/static-hello
docker build \
  --build-arg SOURCE_REVISION="$(git rev-parse --short HEAD)" \
  -t sisyfix-static-hello:local \
  .
```

The remaining pipeline steps (scan gate, SBOM, keyless sign + SLSA provenance
attestation, push to the test ECR repo, verify) are documented in the
image-forge pipeline runbook — added in task #4, once the toolchain is proven
by hand on the provisioned build box.

## Scope / honesty note

- This sample targets **SLSA Build L2** (dedicated build infra + signed
  provenance) plus the **mechanics** of L3 (provenance + attestation).
- Full **L3** (per-run build isolation, and signing-key isolation from build
  steps) is a **deferred next milestone**, not satisfied by building this
  image on a single shared build box.
