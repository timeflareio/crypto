# Release Strategy — `timeflareio/crypto` — Plan

*Settles how this repository versions and releases: what a tag means, what
artefacts it publishes, and what guarantees consumers may rely on.*

> **Status: DONE** — implemented August 2026 on `phase-1-crypto-lift`
> (`release.yml`, `rust/rust-toolchain.toml`, `make vectors-package`, the
> version policy in `README.md`, and the version rule in `CLAUDE.md`).
> **Priority**: P2 — no consumer outside the project pins this module yet.
> **Origin**: multi-repo migration plan (in the monorepo), which delegated
> release strategy to a per-repo plan rather than settling it centrally. All
> open questions ruled by the owner, August 2026.
> **Components**: `.github/workflows/release.yml`, `rust/rust-toolchain.toml`,
> `Makefile`, `README.md`, `CLAUDE.md`.

## 1. What this repository publishes

**Three artefacts per release, from one tag:**

| Artefact | Form | Why |
|---|---|---|
| Go module | tagged source, served by the module proxy | Go consumers build from source, which the guardian requires |
| WASM bundle | `timeflare-crypto-wasm-vX.Y.Z.tgz` + `.sha256` | the TypeScript SDK pins a version and downloads it, so SDK contributors need no Rust toolchain |
| Vector corpus | `timeflare-crypto-vectors-vX.Y.Z.tar.gz` + per-file `.sha256` manifest | downstream reimplementations assert it to prove they interoperate |

The asymmetry is deliberate: Go consumers build from source, everything else
consumes a built artefact.

The corpus ships because it has consumers that this repository's own two suites
do not cover. The mobile client reimplements these primitives natively (its
runtime can execute neither the Go nor the WASM path) and the TypeScript SDK
asserts small-order key rejection. Neither has any other source for the cases,
and "reimplement a primitive and hope" is exactly the failure the corpus exists
to prevent.

## 2. What a version number means

This module has two kinds of change with wildly different blast radii, and
semver alone does not distinguish them:

- **Behaviour-preserving** — refactor, performance, new helper, doc fix.
- **Primitive output changes** — the primitives produce different bytes. This
  invalidates every existing secret, share and hint in the wild. It is a
  protocol change requiring the owner's approval, both implementations and their
  vectors updated together, a `docs/spec.md` prose update in the chain repo, and
  a coordinated roll of every consumer.

**The breaking axis is reserved for the second class and never spent on
anything else**, so seeing it move means exactly one thing. Which position that
axis occupies differs either side of 1.0, because semver expresses 0.x breakage
in the minor position:

| | Behaviour-preserving | Primitive output changes |
|---|---|---|
| **While on 0.x** (current) | PATCH | MINOR |
| **From 1.0.0 onward** | MINOR or PATCH | MAJOR |

One mechanism, not two: no separate `PROTOCOL_VERSION` file. A second signal
would need its own discipline to stay truthful, and the chain repo's
`PROTOCOL_CHANGE.md` checklist already carries the coordination process.

**0.x stays until the owner instructs otherwise.** It means there is no
compatibility promise. `release.yml` refuses any tag outside `v0.*` — not
because 1.0 is far away, but because published tags cannot be unpublished, so
committing to a stability promise by accident is unrecoverable. Crossing it is
deliberately two steps: change the policy, then tag.

## 3. Release mechanics

- **Trigger**: pushing a `vX.Y.Z` tag. Nothing releases on merge.
- **Preconditions in the workflow**, not by convention: the version policy
  guard, then `make verify` and `make test`. Both suites run even though CI
  already ran them on the merge commit, because a tag can point anywhere and a
  release must never ship a drifted implementation pair.
- **Reproducibility**: `rust/rust-toolchain.toml` pins the exact toolchain, so
  the published WASM bundle can be regenerated from its tag. wasm-pack output
  varies with the toolchain that produced it, which makes an unpinned `stable`
  incompatible with a reproducible artefact. Pinning an exact version rather
  than tracking `stable` accepts that toolchain bumps become routine dependency
  work, and that a bump may arrive with lint fixes attached — the right trade in
  the one place reproducibility matters.
- **Release notes are generated**, and state the artefacts, that both suites
  passed against the corpus published in that release, and the compatibility
  position.

## 4. Independence from the chain

**Releases here happen out of lock-step with chain releases.** This is a
dependency others consume; it has its own upgrade path. A release here neither
waits for nor implies a chain release, and nothing in this repository enforces
or checks chain protocol rules.

This is why the corpus is owned here rather than pulled from the chain
(§1): the five files pin primitives implemented in this repository, the
generator that produces them lives here, and the chain asserts none of them. An
earlier design had the chain own the whole corpus and this repo vendor a pinned
copy — which put an implementation's own test data in another repository, made
`make verify` need network access and credentials, and would have forced release
notes to cite a chain tag in order to state their own conformance. Splitting
corpus ownership by which repository implements the behaviour removes all three
problems and leaves this repository self-contained.

The chain keeps its own separate corpus for chain semantics — gas, dials, share
bands, creation fees, wallet derivation — which nothing here mirrors or asserts.

Consumers needing to know which versions belong together read
`COMPATIBILITY.md` in the chain repo. This repository's obligation is to make
its row truthful: each release states what it was proven against, and the
version number signals whether the primitives changed.

## 5. What this plan does not solve

- **Registry publication is deferred.** The WASM bundle is not published to npm
  or any registry. Its only consumer is the TypeScript SDK, whose own release
  plan defers registry publication; if the SDK never publishes, the bundle need
  not either. Revisit when the SDK's decision is made, and note the trap: GitHub
  Packages' npm registry requires a token even to *read* public packages,
  whereas npmjs.org does not.
- **Signing and provenance.** Neither the Go module tags nor the attached assets
  are signed. Checksums protect against corruption, not against a compromised
  release. Sigstore/cosign for assets and signed tags are both plausible and
  both belong to a project-wide supply-chain plan, not to one repository's
  release mechanics.
- **Yanking.** Go modules cannot be unpublished, only retracted (`retract` in
  `go.mod`). The procedure for retracting a bad primitive release is not
  designed here.
- **When 1.0.0 happens.** Deliberately not scheduled — the owner instructs, and
  the guard in `release.yml` makes drifting into it impossible.
- **Repository visibility.** Whether and when this repository becomes public is
  the owner's decision. It changes the consumer story materially — no
  `GOPRIVATE`, no token — but not the release mechanics.
