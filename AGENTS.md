# Alumina — agent instructions

Alumina is a single-binary, statically-linked HTTPS CONNECT egress proxy for
constrained servers. Work here is governed by the fixed repository
specification, not feature growth.

## Rules

- `alumina.md` (repository root) is the sole, byte-canonical governing
  specification (sha256 `322b68ee…5b836`). Never edit it; documents only
  restate or cite it.
- Status is a scoped local testQA candidate — not production-qualified;
  serving-qualification gates stay open (`docs/build-plan.md` owns them).
- Native verification entry point, QA run and prerequisite ownership are
  `qa-package/README.md`; the verify command set is in README "Verification".
  Doc-only changes: `sh scripts/verify.sh docs`.
- `mid` selectors are Linux-only and fail closed off-Linux (reach them via
  `sh scripts/verify.sh boundary phase1` on macOS); `fixtures boot` and the
  `e2e` selectors are directly host-runnable with existing Podman VM
  connections/images (`boundary phase1` never executes E2E).
- Behavioural changes run red→green and preserve the fixed profile: single
  boot owner and single serving owner, two reused 512 KiB per-tunnel buffers,
  no post-boot heap alloc/dealloc, no runtime-surface expansion.
