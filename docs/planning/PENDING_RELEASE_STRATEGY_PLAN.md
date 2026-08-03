# Release Strategy — `timeflareio/crypto` — Plan

*Settles how this repository versions and releases: what a tag means, what
artefacts it publishes, how the WASM bundle reaches the TypeScript SDK, and
what guarantees consumers may rely on. Deliberately a draft — it is authored
now so the questions are visible, and refined once this repository can be
tested in isolation.*

> **Status: refining** — created August 2026 with the phase-1 lift. Open
> questions in §5 are unresolved; this plan is not executable until they are
> ruled and folded into the body.
> **Priority**: P2 — nothing blocks on it while the migration's per-phase
> `v0.0.x` tags serve, but it must land before any consumer outside the
> project pins this module.
> **Origin**: multi-repo migration plan (in the monorepo), §3 and §10.10 —
> release strategy was deliberately delegated to a per-repo plan rather than
> settled centrally.
> **Components**: `Makefile` (release targets), `.github/workflows/` (a new
> `release.yml`), `README.md`, `VECTORS_VERSION`, and the consumer-facing
> contract with `timeflareio/chain`, `timeflareio/guardian` and
> `timeflareio/typescript-sdk`.

## 1. What this repository publishes

Two artefacts per release, from one tag:

- **The Go module** — served directly from tagged source by the module proxy.
  Nothing is built or attached; the tag *is* the artefact. Consumers require
  `github.com/timeflareio/crypto vX.Y.Z`.
- **The WASM bundle** — `wasm-pack` output attached as a release asset
  (`timeflare-crypto-wasm-vX.Y.Z.tgz`), so the TypeScript SDK pins a version
  and downloads it rather than carrying a Rust toolchain.

The asymmetry is deliberate: Go consumers build from source (which the
guardian requires), everything else consumes a built artefact.

## 2. What a version number means here

The hard part is that this module has two kinds of change with wildly
different blast radii, and semver alone does not distinguish them:

- **Behaviour-preserving change** — refactor, performance, new helper, doc fix.
  Ordinary patch or minor.
- **Byte-level primitive change** — the primitives produce different output.
  This invalidates every existing secret, share and hint in the wild. It is a
  protocol change requiring the owner's explicit confirmation, a `docs/spec.md`
  update in the chain repo, matching vector updates, and a coordinated roll of
  every consumer.

A major-version bump signals the second class, but a major bump alone is too
quiet for a change of that consequence. §5 asks what additional signal it
carries.

## 3. Release mechanics (proposed)

- **Trigger**: pushing a `vX.Y.Z` tag. No release-on-merge — releases are
  deliberate.
- **`release.yml`** builds the WASM bundle, attaches it with a SHA-256
  checksum, and generates release notes.
- **Preconditions enforced in the workflow**, not by convention: `make verify`
  and `make test` green on the tagged commit, and `make vectors-verify`
  passing against a *released* chain tag (not a `monorepo:` pin — see
  `VECTORS_VERSION`).
- **Reproducibility**: the WASM bundle should be byte-reproducible from the
  tag. `wasm-pack` output depends on the Rust toolchain version, so this
  requires pinning the toolchain in-repo (`rust-toolchain.toml`) — currently
  absent, and a deliverable of this plan.

## 4. Compatibility contract

`COMPATIBILITY.md` in the chain repo is the join table recording which
versions belong together. This repo's obligation is to make its own row
truthful: every release states the vectors version it was verified against,
and whether the primitives changed.

## 5. Open questions

1. **Does a primitive change get a major bump, or its own signalling
   mechanism?** A major bump is the semver-correct answer but reads as routine
   in a dependency list. Options: reserve majors for primitive changes and
   never use them otherwise (making the signal unambiguous); or add an explicit
   `PROTOCOL_VERSION` file that consumers can assert. *Recommendation*: reserve
   majors, and state the rule in the README — one mechanism is better than two,
   and the chain's `PROTOCOL_CHANGE.md` checklist already carries the process.

2. **Does the Go module and the WASM bundle share one version line?** They are
   built from one tree, so one tag is simplest, but it means a Rust-only change
   bumps the Go module for no reason (and vice versa). *Recommendation*: one
   shared line. Independent lines would need two tag namespaces in one repo and
   buy little; a no-op version bump costs a consumer nothing.

3. **When does `v0.x` become `v1.0.0`?** `v0.x` signals "no compatibility
   promise", which is honest pre-testnet but wrong once third parties run
   guardians. *Recommendation*: `v1.0.0` at the same moment the chain commits
   to a stable wire protocol — this module's stability is not independently
   meaningful.

4. **Is the WASM bundle also published to a registry?** The SDK's own release
   plan defers registry publication. If the SDK never publishes, the bundle
   never needs to either. *Recommendation*: defer, and revisit only when the
   SDK's decision is made — note that GitHub Packages' npm registry requires a
   token even to read public packages.

5. **Does a release require the chain's vectors pin to be a released tag?**
   §3 proposes yes, which means this repo cannot cut a release until the chain
   has cut one. That is correct in steady state but creates a chicken-and-egg
   during the migration, which the `v0.0.x` phase tags side-step.
   *Recommendation*: enforce it from `v0.1.0` onward, exempting the migration's
   `v0.0.x` tags explicitly.

## 6. What this plan does not solve

- **Signing and provenance.** Neither the Go module tags nor the WASM asset are
  signed. Sigstore/cosign for the asset and tag signing are both plausible and
  both out of scope here; they belong to a project-wide supply-chain plan, not
  this repo's release mechanics.
- **Yanking.** Go modules cannot be unpublished, only retracted (`retract` in
  `go.mod`). The procedure for retracting a bad primitive release is not
  designed here.
- **Repository visibility.** Whether and when this repository becomes public is
  the owner's decision and sits outside this plan, though it changes the
  consumer story materially (no `GOPRIVATE`, no token).
